/**
 * LoopGain telemetry receiver.
 *
 * Cloudflare Worker that accepts anonymized telemetry POSTs from the
 * `loopgain` library (via `LoopGain.send_telemetry()`) and serves
 * aggregated reads to the dashboard frontend.
 *
 * Privacy: only structural statistics are stored. No prompts, no
 * completions, no error contents, no customer identity beyond a bearer
 * token mapped to a customer_id.
 *
 * Routes:
 *   POST /v1/aggregate           Ingest one telemetry payload (from the library).
 *                                Server-to-server only; browser-origin requests
 *                                are rejected with 403.
 *   GET  /v1/stats               Aggregated stats for the bearer's customer (30d).
 *                                Includes distinct framework/loop_type/team values
 *                                used to populate dashboard filter dropdowns.
 *   GET  /v1/profiles            Convergence-profile events (optionally per-workload).
 *                                Accepts framework/loop_type/team filter params.
 *   GET  /v1/events              Recent loop events for the rollback log.
 *                                Accepts framework/loop_type/team filter params.
 *   GET  /v1/calibration         Converged loops with eta-prediction snapshots
 *                                (drives the ETA Accuracy dashboard panel).
 *                                Accepts framework/loop_type/team filter params.
 *   GET  /v1/event/:id           Full detail for one event including per-iteration
 *                                trajectory data (drives the Loop Detail scrubber).
 *   GET  /v1/alerts/rules        List the customer's alert rules.
 *   POST /v1/alerts/rules        Create a new alert rule.
 *   PUT  /v1/alerts/rules/:id    Update an existing alert rule.
 *   DELETE /v1/alerts/rules/:id  Delete an alert rule.
 *   GET  /v1/alerts/deliveries   Audit log of alert deliveries (recent first).
 *   GET  /health                 Liveness probe (public, no auth).
 *
 * Cron trigger: a `scheduled` handler runs every minute and evaluates every
 * enabled alert_rule against the last `window_seconds` of loop_events. See
 * `scheduled` export at the bottom of this file.
 *
 * Token rotation is intentionally *not* available over HTTP. Rotation
 * happens only via the operator-side `scripts/rotate-token.mjs` script,
 * which requires Cloudflare account access. This eliminates the
 * "leaked-token can lock the owner out" blast radius.
 *
 * CORS is locked down: only `https://dashboard.loopgain.ai` and a small
 * set of localhost origins are allowed. `/v1/aggregate` does not accept
 * browser-origin requests at all.
 *
 * Rate limiting is enforced via Cloudflare's first-party rate-limit
 * bindings (see wrangler.toml). Two layers:
 *   - per-IP across all routes (catches unauth abuse)
 *   - per-customer on /v1/aggregate (ingestion ceiling per account)
 *   - per-customer on read routes (dashboard polling ceiling)
 *
 * Schema versions:
 *   v1 — initial release.
 *   v2 — adds first_eta_prediction + first_eta_at_iteration on loop_events.
 *        Receiver accepts both v1 and v2 payloads; v1 stores NULL for the
 *        new fields, v2 stores the snapshot when the library captured one.
 *   v3 — adds per_iteration_data (JSON, capped at 256 entries) and three
 *        classification columns: framework, loop_type, team. Receiver
 *        accepts v1/v2/v3; older payloads store NULL for the new fields.
 */

interface RateLimit {
  limit(options: { key: string }): Promise<{ success: boolean }>;
}

export interface Env {
  DB: D1Database;
  // First-party Cloudflare rate-limit bindings. Configured in wrangler.toml.
  AUTH_RL: RateLimit;       // Per-IP across the whole Worker (unauth abuse).
  AGGREGATE_RL: RateLimit;  // Per-customer on POST /v1/aggregate.
  READ_RL: RateLimit;       // Per-customer on GET /v1/* read routes.
}

interface ProfileSummary {
  min: number | null;
  max: number | null;
  median: number | null;
  samples: number;
}

interface PerIterationData {
  convergence_profile: number[];
  error_history: number[];
  truncated: boolean;
  cap: number;
}

interface TelemetryPayload {
  schema_version: number;
  library: string;
  library_version: string;
  workload_id: string | null;
  timestamp_hour: string;
  // v3 — optional classification labels for dashboard filters.
  framework?: string | null;
  loop_type?: string | null;
  team?: string | null;
  loop: {
    outcome: string;
    iterations_used: number;
    gain_margin: number | null;
    savings_vs_fixed_cap: number | null;
    convergence_profile_summary: ProfileSummary;
    rollback_triggered: boolean;
    // v2 — optional. Present iff schema_version >= 2 and the library
    // captured a prediction during the loop.
    first_eta_prediction?: number | null;
    first_eta_at_iteration?: number | null;
  };
  thresholds: {
    fast_converge: number;
    converging: number;
    stalling: number;
    oscillating_upper: number;
  };
  smoothing_window: number;
  // v3 — optional. Per-iteration trajectories capped at 256 entries.
  // Stored as a JSON blob in loop_events.per_iteration_data.
  per_iteration?: PerIterationData | null;
}

const SUPPORTED_SCHEMA_VERSIONS = [1, 2, 3] as const;
const CURRENT_SCHEMA_VERSION = 3;

// Defensive cap on per-iteration arrays at the receiver. The library caps at
// 256 before transmission; mirroring it here protects against malformed or
// hand-crafted payloads that try to write very large blobs.
const PER_ITERATION_RECEIVER_CAP = 1024;

// Hard cap on /v1/aggregate request body. With per_iteration capped at
// 1024 entries × ~12 bytes/number × 2 arrays ≈ 25 KB, plus all the
// scalar fields, a healthy payload is well under 64 KB. 256 KB gives a
// 10x ceiling without inviting D1-row bloat from authed-but-abusive
// customers. Enforced before .json() to fail fast.
const MAX_AGGREGATE_BODY_BYTES = 256 * 1024;

// Length caps on opaque string fields in the payload. Type-checking alone
// would let an authed customer write multi-MB strings into D1 rows.
const MAX_LIBRARY_VERSION_LEN = 64;
const MAX_OUTCOME_LEN = 64;
const MAX_LABEL_LEN = 200; // workload_id, framework, loop_type, team

// CORS allow-list. Only these origins may make browser-origin requests to
// the authenticated read endpoints. /v1/aggregate refuses browser-origin
// requests entirely (see fetch()).
const ALLOWED_ORIGINS = new Set<string>([
  "https://dashboard.loopgain.ai",
  "http://localhost:5173",
  "http://localhost:4173",
  "http://127.0.0.1:5173",
  "http://127.0.0.1:4173",
]);

function corsHeaders(request: Request): Record<string, string> {
  const origin = request.headers.get("Origin") ?? "";
  const headers: Record<string, string> = {
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Authorization, Content-Type",
    "Access-Control-Max-Age": "86400",
    Vary: "Origin",
  };
  if (ALLOWED_ORIGINS.has(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
  }
  return headers;
}

// /health and / are public and intentionally browseable from anywhere.
const PUBLIC_CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

function json(body: unknown, status = 200, extraHeaders: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      "X-Content-Type-Options": "nosniff",
      "Cache-Control": "no-store",
      "Referrer-Policy": "no-referrer",
      ...extraHeaders,
    },
  });
}

function withHeaders(resp: Response, headers: Record<string, string>): Response {
  const out = new Response(resp.body, resp);
  for (const [k, v] of Object.entries(headers)) out.headers.set(k, v);
  return out;
}

async function sha256(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// Constant-time-shaped auth: always compute SHA-256 and always run the DB
// lookup, regardless of whether the Authorization header is present or
// well-formed. The hash of the empty string is a well-known value that we
// never insert into customers.token_hash, so a missing/empty bearer
// resolves to "no row" via the same code path as a malformed bearer.
async function authenticate(request: Request, env: Env): Promise<string | null> {
  const header = request.headers.get("Authorization") ?? "";
  const token = header.startsWith("Bearer ") ? header.slice(7).trim() : "";
  const tokenHash = await sha256(token);
  const row = await env.DB.prepare(
    "SELECT customer_id FROM customers WHERE token_hash = ?",
  )
    .bind(tokenHash)
    .first<{ customer_id: string }>();
  return row?.customer_id ?? null;
}

function clientIp(request: Request): string {
  return request.headers.get("cf-connecting-ip") ?? "unknown";
}

function parseTimestampHour(iso: string): number | null {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  return Math.floor(d.getTime() / 1000);
}

function validatePayload(payload: unknown): payload is TelemetryPayload {
  if (!payload || typeof payload !== "object") return false;
  const p = payload as Partial<TelemetryPayload>;
  if (
    typeof p.schema_version !== "number" ||
    !SUPPORTED_SCHEMA_VERSIONS.includes(
      p.schema_version as (typeof SUPPORTED_SCHEMA_VERSIONS)[number],
    )
  ) {
    return false;
  }
  if (typeof p.library !== "string" || p.library.length > MAX_LABEL_LEN) return false;
  if (typeof p.library_version !== "string" || p.library_version.length > MAX_LIBRARY_VERSION_LEN) return false;
  if (typeof p.timestamp_hour !== "string" || p.timestamp_hour.length > 64) return false;
  if (p.workload_id !== undefined && p.workload_id !== null) {
    if (typeof p.workload_id !== "string" || p.workload_id.length > MAX_LABEL_LEN) return false;
  }
  if (!p.loop || typeof p.loop !== "object") return false;
  if (typeof p.loop.outcome !== "string" || p.loop.outcome.length > MAX_OUTCOME_LEN) return false;
  if (typeof p.loop.iterations_used !== "number") return false;
  if (typeof p.loop.rollback_triggered !== "boolean") return false;
  if (!p.loop.convergence_profile_summary) return false;
  if (!p.thresholds) return false;
  if (typeof p.smoothing_window !== "number") return false;

  // v2 fields (if provided) must be either null or a non-negative integer.
  if (p.schema_version >= 2) {
    const { first_eta_prediction: eta, first_eta_at_iteration: at } = p.loop;
    if (eta !== undefined && eta !== null && (typeof eta !== "number" || eta < 0)) {
      return false;
    }
    if (at !== undefined && at !== null && (typeof at !== "number" || at < 0)) {
      return false;
    }
  }
  // v3 fields (if provided) must match the expected shape.
  if (p.schema_version >= 3) {
    for (const k of ["framework", "loop_type", "team"] as const) {
      const v = p[k];
      if (v !== undefined && v !== null) {
        if (typeof v !== "string" || v.length > MAX_LABEL_LEN) return false;
      }
    }
    if (p.per_iteration !== undefined && p.per_iteration !== null) {
      const pit = p.per_iteration;
      if (typeof pit !== "object") return false;
      if (!Array.isArray(pit.convergence_profile)) return false;
      if (!Array.isArray(pit.error_history)) return false;
      if (typeof pit.truncated !== "boolean") return false;
      if (typeof pit.cap !== "number") return false;
      if (
        pit.convergence_profile.length > PER_ITERATION_RECEIVER_CAP ||
        pit.error_history.length > PER_ITERATION_RECEIVER_CAP
      ) {
        return false;
      }
      // Every entry in the trajectory arrays must be a finite number.
      for (const arr of [pit.convergence_profile, pit.error_history]) {
        for (const v of arr) {
          if (typeof v !== "number" || !Number.isFinite(v)) return false;
        }
      }
    }
  }
  return true;
}

async function handleAggregate(request: Request, env: Env): Promise<Response> {
  if (request.method !== "POST") {
    return json({ error: "method_not_allowed" }, 405);
  }

  // Server-to-server only. Browser-origin requests are rejected outright.
  if (request.headers.get("Origin")) {
    return json({ error: "browser_requests_not_allowed" }, 403);
  }

  const customerId = await authenticate(request, env);
  if (!customerId) return json({ error: "unauthorized" }, 401);

  // Per-customer ingestion ceiling.
  const rl = await env.AGGREGATE_RL.limit({ key: customerId });
  if (!rl.success) return json({ error: "rate_limited" }, 429);

  // Body-size cap. Fail fast before parsing JSON so a malformed-but-huge
  // body doesn't burn CPU. Cloudflare's own ~100 MB ceiling is the only
  // backstop otherwise.
  const lenHeader = request.headers.get("Content-Length");
  if (lenHeader !== null) {
    const len = Number(lenHeader);
    if (!Number.isFinite(len) || len < 0 || len > MAX_AGGREGATE_BODY_BYTES) {
      return json({ error: "payload_too_large" }, 413);
    }
  }

  let parsed: unknown;
  try {
    parsed = await request.json();
  } catch {
    return json({ error: "invalid_json" }, 400);
  }

  if (!validatePayload(parsed)) {
    return json({ error: "invalid_payload" }, 400);
  }
  const payload = parsed;

  const ts = parseTimestampHour(payload.timestamp_hour);
  if (ts === null) return json({ error: "invalid_timestamp_hour" }, 400);

  const summary = payload.loop.convergence_profile_summary;
  // v2 fields default to NULL for v1 payloads or when the library
  // never captured a prediction (target_error=0, non-converging trace).
  const firstEta = payload.loop.first_eta_prediction ?? null;
  const firstEtaAt = payload.loop.first_eta_at_iteration ?? null;
  // v3 fields default to NULL for v1/v2 payloads. per_iteration_data is
  // stored as a JSON string so the dashboard can fetch and parse it.
  const perIterationJson = payload.per_iteration
    ? JSON.stringify(payload.per_iteration)
    : null;
  const framework = payload.framework ?? null;
  const loopType = payload.loop_type ?? null;
  const team = payload.team ?? null;

  // received_at is omitted from the column list; the schema's
  // `DEFAULT (unixepoch())` fills it. 24 columns, 24 bound values.
  await env.DB.prepare(
    `INSERT INTO loop_events (
      customer_id, workload_id, timestamp_hour, library_version,
      outcome, iterations_used, gain_margin, savings_vs_fixed_cap,
      rollback_triggered, profile_min, profile_max, profile_median,
      profile_samples, threshold_fast_converge, threshold_converging,
      threshold_stalling, threshold_oscillating_upper,
      smoothing_window, first_eta_prediction, first_eta_at_iteration,
      per_iteration_data, framework, loop_type, team
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      customerId,
      payload.workload_id,
      ts,
      payload.library_version,
      payload.loop.outcome,
      payload.loop.iterations_used,
      payload.loop.gain_margin,
      payload.loop.savings_vs_fixed_cap,
      payload.loop.rollback_triggered ? 1 : 0,
      summary.min,
      summary.max,
      summary.median,
      summary.samples,
      payload.thresholds.fast_converge,
      payload.thresholds.converging,
      payload.thresholds.stalling,
      payload.thresholds.oscillating_upper,
      payload.smoothing_window,
      firstEta,
      firstEtaAt,
      perIterationJson,
      framework,
      loopType,
      team,
    )
    .run();

  return json({ status: "ok" }, 202);
}

// ── Helper: build a classification-filter clause + bind values ────────
//
// Used by /v1/profiles, /v1/events, /v1/calibration. Returns a SQL
// fragment that goes after WHERE customer_id = ? AND timestamp_hour >= ?
// and the additional bind values to append in order.
function classificationFilters(url: URL): { sql: string; binds: string[] } {
  const parts: string[] = [];
  const binds: string[] = [];
  for (const k of ["framework", "loop_type", "team", "workload_id"] as const) {
    const v = url.searchParams.get(k);
    if (v !== null) {
      parts.push(`AND ${k} = ?`);
      binds.push(v);
    }
  }
  return { sql: parts.join(" "), binds };
}

async function handleStats(request: Request, env: Env): Promise<Response> {
  if (request.method !== "GET") {
    return json({ error: "method_not_allowed" }, 405);
  }

  const customerId = await authenticate(request, env);
  if (!customerId) return json({ error: "unauthorized" }, 401);

  const rl = await env.READ_RL.limit({ key: customerId });
  if (!rl.success) return json({ error: "rate_limited" }, 429);

  const since = Math.floor(Date.now() / 1000) - 30 * 24 * 3600;

  const outcomeStats = await env.DB.prepare(
    `SELECT outcome, COUNT(*) AS count
       FROM loop_events
       WHERE customer_id = ? AND timestamp_hour >= ?
       GROUP BY outcome`,
  )
    .bind(customerId, since)
    .all();

  const totals = await env.DB.prepare(
    `SELECT COUNT(*) AS event_count,
            COALESCE(SUM(iterations_used), 0) AS total_iterations,
            COALESCE(SUM(savings_vs_fixed_cap), 0) AS total_savings,
            COALESCE(SUM(CASE WHEN rollback_triggered = 1 THEN 1 ELSE 0 END), 0) AS rollbacks
       FROM loop_events
       WHERE customer_id = ? AND timestamp_hour >= ?`,
  )
    .bind(customerId, since)
    .first();

  const workloadStats = await env.DB.prepare(
    `SELECT workload_id, COUNT(*) AS count
       FROM loop_events
       WHERE customer_id = ? AND timestamp_hour >= ?
       GROUP BY workload_id
       ORDER BY count DESC
       LIMIT 50`,
  )
    .bind(customerId, since)
    .all();

  // v3: surface distinct classification values so the dashboard can
  // populate filter dropdowns. Each list excludes NULL.
  async function distinctValues(column: "framework" | "loop_type" | "team") {
    const r = await env.DB.prepare(
      `SELECT ${column} AS value, COUNT(*) AS count
         FROM loop_events
         WHERE customer_id = ? AND timestamp_hour >= ? AND ${column} IS NOT NULL
         GROUP BY ${column}
         ORDER BY count DESC
         LIMIT 50`,
    )
      .bind(customerId, since)
      .all();
    return r.results;
  }
  const [frameworks, loopTypes, teams] = await Promise.all([
    distinctValues("framework"),
    distinctValues("loop_type"),
    distinctValues("team"),
  ]);

  return json({
    customer_id: customerId,
    window_days: 30,
    since,
    outcomes: outcomeStats.results,
    totals,
    workloads: workloadStats.results,
    frameworks,
    loop_types: loopTypes,
    teams,
  });
}

async function handleProfiles(request: Request, env: Env): Promise<Response> {
  if (request.method !== "GET") {
    return json({ error: "method_not_allowed" }, 405);
  }

  const customerId = await authenticate(request, env);
  if (!customerId) return json({ error: "unauthorized" }, 401);

  const rl = await env.READ_RL.limit({ key: customerId });
  if (!rl.success) return json({ error: "rate_limited" }, 429);

  const url = new URL(request.url);
  const sinceParam = url.searchParams.get("since_hours");
  const since =
    Math.floor(Date.now() / 1000) -
    (sinceParam ? parseInt(sinceParam, 10) * 3600 : 30 * 24 * 3600);

  // workload_id is one of the classification filters; the helper applies it
  // along with framework/loop_type/team. id is included so the dashboard can
  // open Loop Detail without re-deriving from (workload_id, timestamp_hour).
  const filters = classificationFilters(url);
  const result = await env.DB.prepare(
    `SELECT id, timestamp_hour, workload_id, framework, loop_type, team,
            profile_min, profile_max, profile_median, profile_samples,
            outcome, iterations_used, gain_margin
       FROM loop_events
       WHERE customer_id = ? AND timestamp_hour >= ? ${filters.sql}
       ORDER BY timestamp_hour DESC
       LIMIT 1000`,
  )
    .bind(customerId, since, ...filters.binds)
    .all();

  return json({
    customer_id: customerId,
    workload_id: url.searchParams.get("workload_id"),
    events: result.results,
  });
}

async function handleEvents(request: Request, env: Env): Promise<Response> {
  if (request.method !== "GET") {
    return json({ error: "method_not_allowed" }, 405);
  }

  const customerId = await authenticate(request, env);
  if (!customerId) return json({ error: "unauthorized" }, 401);

  const rl = await env.READ_RL.limit({ key: customerId });
  if (!rl.success) return json({ error: "rate_limited" }, 429);

  const url = new URL(request.url);
  const rollbacksOnly = url.searchParams.get("rollbacks_only") === "true";
  const since = Math.floor(Date.now() / 1000) - 30 * 24 * 3600;

  const filters = classificationFilters(url);
  const rollbackClause = rollbacksOnly ? "AND rollback_triggered = 1" : "";
  const result = await env.DB
    .prepare(
      `SELECT id, timestamp_hour, workload_id, framework, loop_type, team,
              outcome, iterations_used, gain_margin, profile_max,
              savings_vs_fixed_cap, library_version,
              first_eta_prediction, first_eta_at_iteration
         FROM loop_events
         WHERE customer_id = ? AND timestamp_hour >= ?
           ${rollbackClause} ${filters.sql}
         ORDER BY timestamp_hour DESC
         LIMIT 500`,
    )
    .bind(customerId, since, ...filters.binds)
    .all();
  return json({ customer_id: customerId, events: result.results });
}

async function handleCalibration(request: Request, env: Env): Promise<Response> {
  if (request.method !== "GET") {
    return json({ error: "method_not_allowed" }, 405);
  }

  const customerId = await authenticate(request, env);
  if (!customerId) return json({ error: "unauthorized" }, 401);

  const rl = await env.READ_RL.limit({ key: customerId });
  if (!rl.success) return json({ error: "rate_limited" }, 429);

  const url = new URL(request.url);
  const sinceParam = url.searchParams.get("since_hours");
  const since =
    Math.floor(Date.now() / 1000) -
    (sinceParam ? parseInt(sinceParam, 10) * 3600 : 30 * 24 * 3600);

  // Only converged loops with a captured eta prediction. Comparing
  // predicted-vs-actual for diverged/oscillating loops doesn't make sense
  // because they terminated before reaching target.
  const filters = classificationFilters(url);
  const result = await env.DB
    .prepare(
      `SELECT id, timestamp_hour, workload_id, framework, loop_type, team,
              iterations_used, first_eta_prediction, first_eta_at_iteration,
              gain_margin, library_version
         FROM loop_events
         WHERE customer_id = ?
           AND outcome = 'converged'
           AND first_eta_prediction IS NOT NULL
           AND first_eta_at_iteration IS NOT NULL
           AND timestamp_hour >= ? ${filters.sql}
         ORDER BY timestamp_hour DESC
         LIMIT 1000`,
    )
    .bind(customerId, since, ...filters.binds)
    .all();
  return json({
    customer_id: customerId,
    workload_id: url.searchParams.get("workload_id"),
    events: result.results,
  });
}

async function handleEventDetail(
  request: Request,
  env: Env,
  idStr: string,
): Promise<Response> {
  if (request.method !== "GET") {
    return json({ error: "method_not_allowed" }, 405);
  }

  const customerId = await authenticate(request, env);
  if (!customerId) return json({ error: "unauthorized" }, 401);

  const rl = await env.READ_RL.limit({ key: customerId });
  if (!rl.success) return json({ error: "rate_limited" }, 429);

  const id = Number(idStr);
  if (!Number.isInteger(id) || id <= 0) {
    return json({ error: "invalid_event_id" }, 400);
  }

  const row = await env.DB
    .prepare(
      `SELECT id, timestamp_hour, workload_id, framework, loop_type, team,
              library_version, outcome, iterations_used, gain_margin,
              savings_vs_fixed_cap, rollback_triggered, profile_min,
              profile_max, profile_median, profile_samples,
              threshold_fast_converge, threshold_converging,
              threshold_stalling, threshold_oscillating_upper,
              smoothing_window, first_eta_prediction, first_eta_at_iteration,
              per_iteration_data, received_at
         FROM loop_events
         WHERE id = ? AND customer_id = ?`,
    )
    .bind(id, customerId)
    .first<{ per_iteration_data: string | null; [k: string]: unknown }>();

  if (!row) return json({ error: "not_found" }, 404);

  // Parse per_iteration_data back to a structured object so the dashboard
  // doesn't need to JSON.parse a string field. NULL stays null.
  let perIteration: PerIterationData | null = null;
  if (row.per_iteration_data) {
    try {
      perIteration = JSON.parse(row.per_iteration_data) as PerIterationData;
    } catch {
      perIteration = null;
    }
  }

  // Strip the raw JSON column from the response and replace with parsed.
  const { per_iteration_data: _drop, ...rest } = row;
  return json({ event: { ...rest, per_iteration: perIteration } });
}

async function handleHealth(): Promise<Response> {
  return json({
    status: "ok",
    schema_version: CURRENT_SCHEMA_VERSION,
    supported_schema_versions: SUPPORTED_SCHEMA_VERSIONS,
    service: "loopgain-telemetry-receiver",
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // Public liveness routes — no auth, permissive CORS.
    if (url.pathname === "/health" || url.pathname === "/") {
      if (request.method === "OPTIONS") {
        return new Response(null, { status: 204, headers: PUBLIC_CORS_HEADERS });
      }
      return withHeaders(await handleHealth(), PUBLIC_CORS_HEADERS);
    }

    // Per-IP rate limit applies to every authenticated route, including the
    // 401 path — this is what prevents token-spray abuse from an unknown
    // source. Done before any other work.
    const ipRl = await env.AUTH_RL.limit({ key: clientIp(request) });
    if (!ipRl.success) {
      const resp = json({ error: "rate_limited" }, 429);
      return withHeaders(resp, corsHeaders(request));
    }

    // CORS preflight for the restricted endpoints.
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(request) });
    }

    let resp: Response;
    if (url.pathname === "/v1/aggregate") {
      // Server-to-server; no CORS headers attached (the library doesn't
      // need them, and refusing them keeps the route invisible to browsers).
      return handleAggregate(request, env);
    }
    // Path-prefix match for the dynamic detail route so we can extract the id.
    if (url.pathname.startsWith("/v1/event/")) {
      const idStr = url.pathname.slice("/v1/event/".length);
      resp = await handleEventDetail(request, env, idStr);
      return withHeaders(resp, corsHeaders(request));
    }
    // Alert rules CRUD: /v1/alerts/rules and /v1/alerts/rules/:id.
    if (url.pathname === "/v1/alerts/rules") {
      resp = await handleAlertRulesCollection(request, env);
      return withHeaders(resp, corsHeaders(request));
    }
    if (url.pathname.startsWith("/v1/alerts/rules/")) {
      const idStr = url.pathname.slice("/v1/alerts/rules/".length);
      resp = await handleAlertRuleItem(request, env, idStr);
      return withHeaders(resp, corsHeaders(request));
    }
    if (url.pathname === "/v1/alerts/deliveries") {
      resp = await handleAlertDeliveries(request, env);
      return withHeaders(resp, corsHeaders(request));
    }
    switch (url.pathname) {
      case "/v1/stats":
        resp = await handleStats(request, env);
        break;
      case "/v1/profiles":
        resp = await handleProfiles(request, env);
        break;
      case "/v1/events":
        resp = await handleEvents(request, env);
        break;
      case "/v1/calibration":
        resp = await handleCalibration(request, env);
        break;
      default:
        resp = json({ error: "not_found" }, 404);
    }
    return withHeaders(resp, corsHeaders(request));
  },

  // Scheduled cron handler — evaluates every enabled alert_rule and fires
  // webhook deliveries that match. Runs every minute (see wrangler.toml).
  async scheduled(_event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(evaluateAlertRules(env));
  },
};

// ── Alert subsystem ───────────────────────────────────────────────────

/** Predicate types supported in v1. New types can be added without a
 *  schema migration since predicates are stored as JSON. */
type AlertPredicate =
  | {
      metric: "outcome_count";
      outcome: string;
      operator: ">" | ">=" | "<" | "<=" | "=";
      threshold: number;
    }
  | {
      metric: "rollback_count";
      operator: ">" | ">=" | "<" | "<=" | "=";
      threshold: number;
    }
  | {
      metric: "rollback_rate";
      operator: ">" | ">=" | "<" | "<=" | "=";
      threshold: number; // 0..1
    }
  | {
      metric: "gain_margin_min";
      operator: "<" | "<=";
      threshold: number;
    };

interface AlertFilter {
  workload_id?: string;
  framework?: string;
  loop_type?: string;
  team?: string;
}

interface AlertRuleRow {
  id: number;
  customer_id: string;
  name: string;
  enabled: number;
  predicate: string;
  filter: string | null;
  window_seconds: number;
  cooldown_seconds: number;
  action_type: string;
  action_url: string;
  action_secret: string | null;
  created_at: number;
  updated_at: number;
  last_fired_at: number | null;
}

const VALID_OPERATORS = new Set([">", ">=", "<", "<=", "="]);
const MAX_RULES_PER_CUSTOMER = 50;

function validatePredicate(p: unknown): p is AlertPredicate {
  if (!p || typeof p !== "object") return false;
  const x = p as Record<string, unknown>;
  if (typeof x.operator !== "string" || !VALID_OPERATORS.has(x.operator)) return false;
  if (typeof x.threshold !== "number" || !Number.isFinite(x.threshold)) return false;
  switch (x.metric) {
    case "outcome_count":
      return typeof x.outcome === "string" && x.outcome.length > 0;
    case "rollback_count":
    case "gain_margin_min":
      return true;
    case "rollback_rate":
      return x.threshold >= 0 && x.threshold <= 1;
    default:
      return false;
  }
}

function validateFilter(f: unknown): f is AlertFilter {
  if (f === null || f === undefined) return true;
  if (typeof f !== "object") return false;
  for (const k of ["workload_id", "framework", "loop_type", "team"] as const) {
    const v = (f as Record<string, unknown>)[k];
    if (v !== undefined && v !== null && typeof v !== "string") return false;
  }
  return true;
}

/** Reject obviously-private destinations to limit SSRF blast radius.
 *  Cloudflare Workers can't reach customer internal infra anyway, but a
 *  customer mis-pasting an internal URL would otherwise hammer their own
 *  egress. https-only is enforced on the public internet.
 *
 *  Coverage:
 *    - scheme: only https
 *    - IPv4 private/loopback/link-local: 10/8, 172.16/12, 192.168/16, 127/8, 0.0.0.0, 169.254/16
 *    - IPv6 literals: refused entirely (loopback ::1, link-local fe80::,
 *      ULA fc00::/7 — and any future special range without a per-range
 *      check). Customers wanting an IPv6 webhook can use a hostname.
 *    - Numeric-encoded IPv4 (e.g., http://2130706433/ → 127.0.0.1):
 *      refused entirely. Hostnames that are pure decimal/hex are not
 *      valid public hostnames anyway. */
function validateActionUrl(raw: string): string | null {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return "invalid_url";
  }
  if (u.protocol !== "https:") return "https_required";
  const host = u.hostname.toLowerCase();

  // IPv6 literals — URL parses them with surrounding brackets stripped by
  // `hostname`. The reliable detection is "contains a colon", since no
  // valid DNS hostname or IPv4 address contains one.
  if (host.includes(":")) return "private_url_not_allowed";

  // Numeric-only hostnames (decimal, hex, octal) can encode arbitrary IPv4
  // addresses including private ranges. Reject outright — public hostnames
  // are never purely numeric.
  if (/^[0-9]+$/.test(host) || /^0x[0-9a-f]+$/i.test(host)) {
    return "private_url_not_allowed";
  }

  if (
    host === "localhost" ||
    host === "127.0.0.1" ||
    host === "0.0.0.0" ||
    host.endsWith(".local") ||
    host.startsWith("10.") ||
    host.startsWith("127.") ||
    host.startsWith("192.168.") ||
    host.startsWith("169.254.") ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(host)
  ) {
    return "private_url_not_allowed";
  }
  return null;
}

interface AlertRulePayload {
  name: string;
  enabled?: boolean;
  predicate: AlertPredicate;
  filter?: AlertFilter | null;
  window_seconds: number;
  cooldown_seconds?: number;
  action_type: "webhook";
  action_url: string;
  action_secret?: string | null;
}

function validateRulePayload(body: unknown): { ok: true; value: AlertRulePayload } | { ok: false; error: string } {
  if (!body || typeof body !== "object") return { ok: false, error: "invalid_body" };
  const b = body as Record<string, unknown>;
  if (typeof b.name !== "string" || b.name.length === 0 || b.name.length > 200) {
    return { ok: false, error: "invalid_name" };
  }
  if (b.enabled !== undefined && typeof b.enabled !== "boolean") {
    return { ok: false, error: "invalid_enabled" };
  }
  if (!validatePredicate(b.predicate)) return { ok: false, error: "invalid_predicate" };
  if (!validateFilter(b.filter)) return { ok: false, error: "invalid_filter" };
  if (
    typeof b.window_seconds !== "number" ||
    !Number.isInteger(b.window_seconds) ||
    b.window_seconds < 60 ||
    b.window_seconds > 86400
  ) {
    return { ok: false, error: "invalid_window_seconds" };
  }
  if (b.cooldown_seconds !== undefined) {
    if (
      typeof b.cooldown_seconds !== "number" ||
      !Number.isInteger(b.cooldown_seconds) ||
      b.cooldown_seconds < 0 ||
      b.cooldown_seconds > 86400
    ) {
      return { ok: false, error: "invalid_cooldown_seconds" };
    }
  }
  if (b.action_type !== "webhook") return { ok: false, error: "invalid_action_type" };
  if (typeof b.action_url !== "string") return { ok: false, error: "invalid_action_url" };
  const urlErr = validateActionUrl(b.action_url);
  if (urlErr) return { ok: false, error: urlErr };
  if (
    b.action_secret !== undefined &&
    b.action_secret !== null &&
    (typeof b.action_secret !== "string" || b.action_secret.length > 256)
  ) {
    return { ok: false, error: "invalid_action_secret" };
  }
  return { ok: true, value: b as unknown as AlertRulePayload };
}

function ruleRowToWire(row: AlertRuleRow): Record<string, unknown> {
  return {
    id: row.id,
    name: row.name,
    enabled: row.enabled === 1,
    predicate: JSON.parse(row.predicate),
    filter: row.filter ? JSON.parse(row.filter) : null,
    window_seconds: row.window_seconds,
    cooldown_seconds: row.cooldown_seconds,
    action_type: row.action_type,
    action_url: row.action_url,
    // action_secret intentionally omitted from wire — write-only.
    created_at: row.created_at,
    updated_at: row.updated_at,
    last_fired_at: row.last_fired_at,
  };
}

async function handleAlertRulesCollection(
  request: Request,
  env: Env,
): Promise<Response> {
  const customerId = await authenticate(request, env);
  if (!customerId) return json({ error: "unauthorized" }, 401);
  const rl = await env.READ_RL.limit({ key: customerId });
  if (!rl.success) return json({ error: "rate_limited" }, 429);

  if (request.method === "GET") {
    const result = await env.DB
      .prepare(
        `SELECT id, customer_id, name, enabled, predicate, filter,
                window_seconds, cooldown_seconds, action_type, action_url,
                action_secret, created_at, updated_at, last_fired_at
           FROM alert_rules
           WHERE customer_id = ?
           ORDER BY id ASC`,
      )
      .bind(customerId)
      .all<AlertRuleRow>();
    return json({ rules: (result.results ?? []).map(ruleRowToWire) });
  }
  if (request.method === "POST") {
    const count = await env.DB
      .prepare(`SELECT COUNT(*) AS n FROM alert_rules WHERE customer_id = ?`)
      .bind(customerId)
      .first<{ n: number }>();
    if ((count?.n ?? 0) >= MAX_RULES_PER_CUSTOMER) {
      return json({ error: "rule_limit_reached", limit: MAX_RULES_PER_CUSTOMER }, 409);
    }
    let body: unknown;
    try {
      body = await request.json();
    } catch {
      return json({ error: "invalid_json" }, 400);
    }
    const v = validateRulePayload(body);
    if (!v.ok) return json({ error: v.error }, 400);
    const r = v.value;
    const inserted = await env.DB
      .prepare(
        `INSERT INTO alert_rules (
           customer_id, name, enabled, predicate, filter,
           window_seconds, cooldown_seconds, action_type, action_url, action_secret
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         RETURNING id, customer_id, name, enabled, predicate, filter,
                   window_seconds, cooldown_seconds, action_type, action_url,
                   action_secret, created_at, updated_at, last_fired_at`,
      )
      .bind(
        customerId,
        r.name,
        r.enabled === false ? 0 : 1,
        JSON.stringify(r.predicate),
        r.filter ? JSON.stringify(r.filter) : null,
        r.window_seconds,
        r.cooldown_seconds ?? 600,
        r.action_type,
        r.action_url,
        r.action_secret ?? null,
      )
      .first<AlertRuleRow>();
    if (!inserted) return json({ error: "insert_failed" }, 500);
    return json({ rule: ruleRowToWire(inserted) }, 201);
  }
  return json({ error: "method_not_allowed" }, 405);
}

async function handleAlertRuleItem(
  request: Request,
  env: Env,
  idStr: string,
): Promise<Response> {
  const customerId = await authenticate(request, env);
  if (!customerId) return json({ error: "unauthorized" }, 401);
  const rl = await env.READ_RL.limit({ key: customerId });
  if (!rl.success) return json({ error: "rate_limited" }, 429);

  const id = Number(idStr);
  if (!Number.isInteger(id) || id <= 0) return json({ error: "invalid_rule_id" }, 400);

  if (request.method === "PUT") {
    let body: unknown;
    try {
      body = await request.json();
    } catch {
      return json({ error: "invalid_json" }, 400);
    }
    const v = validateRulePayload(body);
    if (!v.ok) return json({ error: v.error }, 400);
    const r = v.value;
    const updated = await env.DB
      .prepare(
        `UPDATE alert_rules
            SET name = ?, enabled = ?, predicate = ?, filter = ?,
                window_seconds = ?, cooldown_seconds = ?, action_type = ?,
                action_url = ?, action_secret = ?, updated_at = unixepoch()
          WHERE id = ? AND customer_id = ?
          RETURNING id, customer_id, name, enabled, predicate, filter,
                    window_seconds, cooldown_seconds, action_type, action_url,
                    action_secret, created_at, updated_at, last_fired_at`,
      )
      .bind(
        r.name,
        r.enabled === false ? 0 : 1,
        JSON.stringify(r.predicate),
        r.filter ? JSON.stringify(r.filter) : null,
        r.window_seconds,
        r.cooldown_seconds ?? 600,
        r.action_type,
        r.action_url,
        r.action_secret ?? null,
        id,
        customerId,
      )
      .first<AlertRuleRow>();
    if (!updated) return json({ error: "not_found" }, 404);
    return json({ rule: ruleRowToWire(updated) });
  }
  if (request.method === "DELETE") {
    const result = await env.DB
      .prepare(`DELETE FROM alert_rules WHERE id = ? AND customer_id = ?`)
      .bind(id, customerId)
      .run();
    if ((result.meta.changes ?? 0) === 0) return json({ error: "not_found" }, 404);
    return json({ deleted: id });
  }
  return json({ error: "method_not_allowed" }, 405);
}

async function handleAlertDeliveries(request: Request, env: Env): Promise<Response> {
  if (request.method !== "GET") return json({ error: "method_not_allowed" }, 405);
  const customerId = await authenticate(request, env);
  if (!customerId) return json({ error: "unauthorized" }, 401);
  const rl = await env.READ_RL.limit({ key: customerId });
  if (!rl.success) return json({ error: "rate_limited" }, 429);

  const result = await env.DB
    .prepare(
      `SELECT d.id, d.rule_id, d.fired_at, d.match_value, d.match_count,
              d.delivery_status, d.delivery_status_code, d.delivery_error,
              r.name AS rule_name
         FROM alert_deliveries d
         JOIN alert_rules r ON r.id = d.rule_id
         WHERE d.customer_id = ?
         ORDER BY d.fired_at DESC
         LIMIT 200`,
    )
    .bind(customerId)
    .all();
  return json({ deliveries: result.results });
}

// ── Cron evaluator ────────────────────────────────────────────────────

interface EvaluationResult {
  match: boolean;
  matchValue: number;
  matchCount: number;
}

/** Build the WHERE clause (after `customer_id = ? AND timestamp_hour >= ?`)
 *  for the rule's filter, plus the bind values to append. */
function buildFilterClause(
  filter: AlertFilter | null,
): { sql: string; binds: string[] } {
  if (!filter) return { sql: "", binds: [] };
  const parts: string[] = [];
  const binds: string[] = [];
  for (const k of ["workload_id", "framework", "loop_type", "team"] as const) {
    const v = filter[k];
    if (v) {
      parts.push(`AND ${k} = ?`);
      binds.push(v);
    }
  }
  return { sql: parts.join(" "), binds };
}

function compareOp(op: string, value: number, threshold: number): boolean {
  switch (op) {
    case ">":
      return value > threshold;
    case ">=":
      return value >= threshold;
    case "<":
      return value < threshold;
    case "<=":
      return value <= threshold;
    case "=":
      return value === threshold;
  }
  return false;
}

async function evaluateRule(
  env: Env,
  rule: AlertRuleRow,
  now: number,
): Promise<EvaluationResult> {
  const since = now - rule.window_seconds;
  const predicate = JSON.parse(rule.predicate) as AlertPredicate;
  const filter = rule.filter ? (JSON.parse(rule.filter) as AlertFilter) : null;
  const f = buildFilterClause(filter);

  switch (predicate.metric) {
    case "outcome_count": {
      const r = await env.DB
        .prepare(
          `SELECT COUNT(*) AS n FROM loop_events
            WHERE customer_id = ? AND timestamp_hour >= ?
              AND outcome = ? ${f.sql}`,
        )
        .bind(rule.customer_id, since, predicate.outcome, ...f.binds)
        .first<{ n: number }>();
      const n = r?.n ?? 0;
      return {
        match: compareOp(predicate.operator, n, predicate.threshold),
        matchValue: n,
        matchCount: n,
      };
    }
    case "rollback_count": {
      const r = await env.DB
        .prepare(
          `SELECT COUNT(*) AS n FROM loop_events
            WHERE customer_id = ? AND timestamp_hour >= ?
              AND rollback_triggered = 1 ${f.sql}`,
        )
        .bind(rule.customer_id, since, ...f.binds)
        .first<{ n: number }>();
      const n = r?.n ?? 0;
      return {
        match: compareOp(predicate.operator, n, predicate.threshold),
        matchValue: n,
        matchCount: n,
      };
    }
    case "rollback_rate": {
      const r = await env.DB
        .prepare(
          `SELECT
              COUNT(*) AS total,
              SUM(CASE WHEN rollback_triggered = 1 THEN 1 ELSE 0 END) AS rb
            FROM loop_events
            WHERE customer_id = ? AND timestamp_hour >= ? ${f.sql}`,
        )
        .bind(rule.customer_id, since, ...f.binds)
        .first<{ total: number; rb: number }>();
      const total = r?.total ?? 0;
      const rb = r?.rb ?? 0;
      const rate = total > 0 ? rb / total : 0;
      return {
        match: total > 0 && compareOp(predicate.operator, rate, predicate.threshold),
        matchValue: rate,
        matchCount: rb,
      };
    }
    case "gain_margin_min": {
      const r = await env.DB
        .prepare(
          `SELECT COUNT(*) AS n, MIN(gain_margin) AS gm FROM loop_events
            WHERE customer_id = ? AND timestamp_hour >= ?
              AND gain_margin IS NOT NULL
              AND ${predicate.operator === "<" ? "gain_margin <" : "gain_margin <="} ?
              ${f.sql}`,
        )
        .bind(rule.customer_id, since, predicate.threshold, ...f.binds)
        .first<{ n: number; gm: number | null }>();
      const n = r?.n ?? 0;
      return {
        match: n > 0,
        matchValue: r?.gm ?? predicate.threshold,
        matchCount: n,
      };
    }
  }
}

async function deliverWebhook(
  rule: AlertRuleRow,
  result: EvaluationResult,
  firedAt: number,
): Promise<{ status: "sent" | "failed"; statusCode: number | null; error: string | null }> {
  // Re-validate at fire time: rules persist, but validateActionUrl can
  // evolve (e.g., a new private range added). A previously-permitted URL
  // that now resolves to "private_url_not_allowed" is short-circuited
  // here rather than fired.
  const urlErr = validateActionUrl(rule.action_url);
  if (urlErr) {
    return { status: "failed", statusCode: null, error: `url_rejected:${urlErr}` };
  }
  const predicate = JSON.parse(rule.predicate);
  const filter = rule.filter ? JSON.parse(rule.filter) : null;
  const payload = {
    rule_id: rule.id,
    rule_name: rule.name,
    customer_id: rule.customer_id,
    fired_at: firedAt,
    predicate,
    filter,
    window_seconds: rule.window_seconds,
    match_value: result.matchValue,
    match_count: result.matchCount,
  };
  try {
    const resp = await fetch(rule.action_url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "User-Agent": "loopgain-alerts/1.0",
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(5000),
    });
    if (resp.status >= 200 && resp.status < 300) {
      return { status: "sent", statusCode: resp.status, error: null };
    }
    return {
      status: "failed",
      statusCode: resp.status,
      error: `non_2xx`,
    };
  } catch (err) {
    return {
      status: "failed",
      statusCode: null,
      error: err instanceof Error ? err.message.slice(0, 200) : "unknown_error",
    };
  }
}

async function evaluateAlertRules(env: Env): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  // Pull all enabled rules. Filter cooldown in memory so we can record a
  // 'skipped_cooldown' delivery row when a rule would have fired.
  const result = await env.DB
    .prepare(
      `SELECT id, customer_id, name, enabled, predicate, filter,
              window_seconds, cooldown_seconds, action_type, action_url,
              action_secret, created_at, updated_at, last_fired_at
         FROM alert_rules
         WHERE enabled = 1`,
    )
    .all<AlertRuleRow>();

  const rules = result.results ?? [];
  for (const rule of rules) {
    let evalResult: EvaluationResult;
    try {
      evalResult = await evaluateRule(env, rule, now);
    } catch {
      continue;
    }
    if (!evalResult.match) continue;
    const inCooldown =
      rule.last_fired_at !== null &&
      now - rule.last_fired_at < rule.cooldown_seconds;
    if (inCooldown) {
      await env.DB
        .prepare(
          `INSERT INTO alert_deliveries
             (rule_id, customer_id, fired_at, match_value, match_count, delivery_status)
           VALUES (?, ?, ?, ?, ?, 'skipped_cooldown')`,
        )
        .bind(rule.id, rule.customer_id, now, evalResult.matchValue, evalResult.matchCount)
        .run();
      continue;
    }
    const delivery = await deliverWebhook(rule, evalResult, now);
    await env.DB
      .prepare(
        `INSERT INTO alert_deliveries
           (rule_id, customer_id, fired_at, match_value, match_count,
            delivery_status, delivery_status_code, delivery_error)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        rule.id,
        rule.customer_id,
        now,
        evalResult.matchValue,
        evalResult.matchCount,
        delivery.status,
        delivery.statusCode,
        delivery.error,
      )
      .run();
    if (delivery.status === "sent") {
      await env.DB
        .prepare(`UPDATE alert_rules SET last_fired_at = ? WHERE id = ?`)
        .bind(now, rule.id)
        .run();
    }
  }
}
