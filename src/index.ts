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
 *   POST /v1/aggregate      Ingest one telemetry payload (from the library).
 *                           Server-to-server only; browser-origin requests
 *                           are rejected with 403.
 *   GET  /v1/stats          Aggregated stats for the bearer's customer (30d).
 *   GET  /v1/profiles       Convergence-profile events (optionally per-workload).
 *   GET  /v1/events         Recent loop events for the rollback log.
 *   GET  /v1/calibration    Converged loops with eta-prediction snapshots
 *                           (drives the ETA Accuracy dashboard panel).
 *   GET  /health            Liveness probe (public, no auth).
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

interface TelemetryPayload {
  schema_version: number;
  library: string;
  library_version: string;
  workload_id: string | null;
  timestamp_hour: string;
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
}

const SUPPORTED_SCHEMA_VERSIONS = [1, 2] as const;
const CURRENT_SCHEMA_VERSION = 2;

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
    headers: { "Content-Type": "application/json", ...extraHeaders },
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
  if (typeof p.library !== "string") return false;
  if (typeof p.library_version !== "string") return false;
  if (typeof p.timestamp_hour !== "string") return false;
  if (!p.loop || typeof p.loop !== "object") return false;
  if (typeof p.loop.outcome !== "string") return false;
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

  // received_at is omitted from the column list; the schema's
  // `DEFAULT (unixepoch())` fills it. 20 columns, 20 bound values.
  await env.DB.prepare(
    `INSERT INTO loop_events (
      customer_id, workload_id, timestamp_hour, library_version,
      outcome, iterations_used, gain_margin, savings_vs_fixed_cap,
      rollback_triggered, profile_min, profile_max, profile_median,
      profile_samples, threshold_fast_converge, threshold_converging,
      threshold_stalling, threshold_oscillating_upper,
      smoothing_window, first_eta_prediction, first_eta_at_iteration
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
    )
    .run();

  return json({ status: "ok" }, 202);
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

  return json({
    customer_id: customerId,
    window_days: 30,
    since,
    outcomes: outcomeStats.results,
    totals,
    workloads: workloadStats.results,
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
  const workloadId = url.searchParams.get("workload_id");
  const sinceParam = url.searchParams.get("since_hours");
  const since =
    Math.floor(Date.now() / 1000) -
    (sinceParam ? parseInt(sinceParam, 10) * 3600 : 30 * 24 * 3600);

  const query = workloadId
    ? `SELECT timestamp_hour, profile_min, profile_max, profile_median,
              profile_samples, outcome, iterations_used, gain_margin
         FROM loop_events
         WHERE customer_id = ? AND workload_id = ? AND timestamp_hour >= ?
         ORDER BY timestamp_hour DESC
         LIMIT 1000`
    : `SELECT timestamp_hour, workload_id, profile_min, profile_max, profile_median,
              profile_samples, outcome, iterations_used, gain_margin
         FROM loop_events
         WHERE customer_id = ? AND timestamp_hour >= ?
         ORDER BY timestamp_hour DESC
         LIMIT 1000`;

  const stmt = workloadId
    ? env.DB.prepare(query).bind(customerId, workloadId, since)
    : env.DB.prepare(query).bind(customerId, since);
  const result = await stmt.all();

  return json({
    customer_id: customerId,
    workload_id: workloadId,
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

  const query = rollbacksOnly
    ? `SELECT timestamp_hour, workload_id, outcome, iterations_used,
              gain_margin, profile_max, savings_vs_fixed_cap, library_version,
              first_eta_prediction, first_eta_at_iteration
         FROM loop_events
         WHERE customer_id = ? AND timestamp_hour >= ? AND rollback_triggered = 1
         ORDER BY timestamp_hour DESC
         LIMIT 500`
    : `SELECT timestamp_hour, workload_id, outcome, iterations_used,
              gain_margin, profile_max, savings_vs_fixed_cap, library_version,
              first_eta_prediction, first_eta_at_iteration
         FROM loop_events
         WHERE customer_id = ? AND timestamp_hour >= ?
         ORDER BY timestamp_hour DESC
         LIMIT 500`;

  const result = await env.DB.prepare(query).bind(customerId, since).all();
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
  const workloadId = url.searchParams.get("workload_id");
  const sinceParam = url.searchParams.get("since_hours");
  const since =
    Math.floor(Date.now() / 1000) -
    (sinceParam ? parseInt(sinceParam, 10) * 3600 : 30 * 24 * 3600);

  // Only converged loops with a captured eta prediction. Comparing
  // predicted-vs-actual for diverged/oscillating loops doesn't make sense
  // because they terminated before reaching target.
  const base = `SELECT timestamp_hour, workload_id, iterations_used,
                       first_eta_prediction, first_eta_at_iteration,
                       gain_margin, library_version
                  FROM loop_events
                  WHERE customer_id = ?
                    AND outcome = 'converged'
                    AND first_eta_prediction IS NOT NULL
                    AND first_eta_at_iteration IS NOT NULL
                    AND timestamp_hour >= ?`;

  const stmt = workloadId
    ? env.DB
        .prepare(`${base} AND workload_id = ? ORDER BY timestamp_hour DESC LIMIT 1000`)
        .bind(customerId, since, workloadId)
    : env.DB
        .prepare(`${base} ORDER BY timestamp_hour DESC LIMIT 1000`)
        .bind(customerId, since);

  const result = await stmt.all();
  return json({
    customer_id: customerId,
    workload_id: workloadId,
    events: result.results,
  });
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
    switch (url.pathname) {
      case "/v1/aggregate":
        // Server-to-server; no CORS headers attached (the library doesn't
        // need them, and refusing them keeps the route invisible to browsers).
        return handleAggregate(request, env);
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
};
