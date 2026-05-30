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
 *   POST /v1/funnel              Ingest a batch of ANONYMOUS funnel events from
 *                                the OSS library's `loopgain.funnel` module.
 *                                No auth, no bearer token, no IP stored —
 *                                separate table from /v1/aggregate. See the
 *                                "Funnel telemetry" section below.
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
  PUBLIC_RL: RateLimit;     // Per-IP on /v1/public/benchmark/* (unauth bench view).
  FUNNEL_RL: RateLimit;     // Per-IP on POST /v1/funnel (unauth anonymous funnel).
}

// Hardcoded customer_id for the public benchmark view served at
// /v1/public/benchmark/*. Anyone can read this tenant's data unauth'd —
// it's the canonical bench-run dataset published alongside
// github.com/loopgain-ai/loopgain-bench. NO other tenant data is exposed
// by the public routes; the customer_id is *not* taken from a parameter.
const BENCH_CUSTOMER_ID = "cust_7931de9f766452ac";

// CORS headers applied to every /v1/public/benchmark/* response. Cache-
// Control is set per-response (see `publicCacheControl`) so we don't poison
// the edge with an empty/transient response.
const BENCH_PUBLIC_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

// 5-min edge cache is generous: the bench dataset is static (2,000 trials
// from a one-shot bench run); the only reason to re-fetch is dashboard
// reloads, and those benefit from cache hits. But: empty responses (no
// rows yet, transient zero-state during an upload) MUST NOT be cached,
// otherwise a viewer who lands during the upload window sees an empty
// dashboard for the next 5 minutes.
const BENCH_CACHE_OK = "public, max-age=300";
const BENCH_CACHE_SKIP = "no-store";

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
  // v3.1 — optional. Real measured $ saved on this trial when the caller
  // has paired-baseline data (currently: the bench, which has B5/B10/B20
  // costs alongside each LG run). Real customers don't populate it; the
  // dashboard falls back to iter-count × $/iter extrapolation when NULL.
  actual_dollars_saved?: number | null;
  // v3.2 — optional. Real measured $ spent on this trial (LG-side cost).
  // Companion to actual_dollars_saved; same population semantics. Lets
  // the Waste panel show measured spend instead of iter × $/iter extrap.
  actual_dollars_spent?: number | null;
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
    // v3.1 actual_dollars_saved: finite non-negative number, or null.
    if (p.actual_dollars_saved !== undefined && p.actual_dollars_saved !== null) {
      const v = p.actual_dollars_saved;
      if (typeof v !== "number" || !Number.isFinite(v) || v < 0) return false;
    }
    // v3.2 actual_dollars_spent: finite non-negative number, or null.
    if (p.actual_dollars_spent !== undefined && p.actual_dollars_spent !== null) {
      const v = p.actual_dollars_spent;
      if (typeof v !== "number" || !Number.isFinite(v) || v < 0) return false;
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
  const actualDollarsSaved = payload.actual_dollars_saved ?? null;
  const actualDollarsSpent = payload.actual_dollars_spent ?? null;

  // received_at is omitted from the column list; the schema's
  // `DEFAULT (unixepoch())` fills it. 26 columns, 26 bound values.
  await env.DB.prepare(
    `INSERT INTO loop_events (
      customer_id, workload_id, timestamp_hour, library_version,
      outcome, iterations_used, gain_margin, savings_vs_fixed_cap,
      rollback_triggered, profile_min, profile_max, profile_median,
      profile_samples, threshold_fast_converge, threshold_converging,
      threshold_stalling, threshold_oscillating_upper,
      smoothing_window, first_eta_prediction, first_eta_at_iteration,
      per_iteration_data, framework, loop_type, team,
      actual_dollars_saved, actual_dollars_spent
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
      actualDollarsSaved,
      actualDollarsSpent,
    )
    .run();

  return json({ status: "ok" }, 202);
}

// ── Funnel telemetry (anonymous, unauthenticated) ─────────────────────
//
// Completely separate ingest path from /v1/aggregate above. The product
// route ships a *customer's own* loop data under *their* bearer token; this
// route receives the *maintainer's* anonymous adoption-funnel events
// (install → first observe() → recurring use) from the open-source library's
// `loopgain.funnel` module. See loopgain-core/TELEMETRY.md for the contract.
//
// Privacy posture, enforced here:
//   - NO bearer-token auth (the data is anonymous; there is no customer).
//   - NO IP address is ever stored. The client IP is used only as an
//     ephemeral per-IP rate-limit key in the router (FUNNEL_RL); it never
//     reaches a D1 column.
//   - Stored fields are anonymous counters only: a locally-generated random
//     instance id (not derived from any identifier), hour-bucketed
//     timestamps, library/python/os versions, adapter name, and coarse
//     outcome counts.
//
// Batch shape (POST JSON):
//   { schema_version: 1, library: "loopgain", events: [ {event}, ... ] }

// Bumped only on a breaking change to the funnel event format. Mirrors
// FUNNEL_SCHEMA_VERSION in loopgain.funnel; independent of the product
// SUPPORTED_SCHEMA_VERSIONS above.
const FUNNEL_SCHEMA_VERSION = 1;

// A single install emits a handful of events per session, flushed in small
// batches. 64 is well above any honest batch while bounding abuse.
const MAX_FUNNEL_EVENTS = 64;

// Funnel payloads are tiny (a few small JSON objects). 64 KB is a 10x+
// ceiling; enforced before .json() so a huge body fails fast.
const MAX_FUNNEL_BODY_BYTES = 64 * 1024;

// instance_id is a uuid4().hex — exactly 32 hex chars. Validating the shape
// keeps junk out of the install-counting column.
const FUNNEL_INSTANCE_ID_RE = /^[0-9a-fA-F]{32}$/;

// Length caps on the short opaque string fields (python, os, event, outcome
// bucket names). Bounded so type-checking alone can't let a hostile caller
// write multi-KB strings into rows.
const MAX_FUNNEL_SHORT_LEN = 64;

// Coarse outcome distribution has a small, stable key set
// (converged / oscillating / diverged / stalled / max_iterations / other).
// 16 leaves headroom for additive buckets without inviting blob bloat.
const MAX_FUNNEL_OUTCOME_KEYS = 16;

interface FunnelRow {
  event: string;
  instance_id: string;
  ts_hour: number; // unix seconds, hour-bucketed
  library_version: string;
  python: string | null;
  os: string | null;
  adapter: string | null; // session events only, else NULL
  session_seq: number | null; // session events only, else NULL
  outcomes: string | null; // JSON, session events only, else NULL
}

// Optional bounded string: undefined/null → null; a too-long or non-string
// value fails the whole event. Used for python / os / adapter.
function optBoundedString(
  v: unknown,
  max: number,
): { ok: boolean; value: string | null } {
  if (v === undefined || v === null) return { ok: true, value: null };
  if (typeof v !== "string" || v.length > max) return { ok: false, value: null };
  return { ok: true, value: v };
}

// Optional coarse outcome map: { "converged": 3, "oscillating": 1, ... }.
// Keys are short bucket names; values are non-negative integers. Serialized
// to a JSON string for storage. undefined/null → null.
function parseFunnelOutcomes(v: unknown): { ok: boolean; value: string | null } {
  if (v === undefined || v === null) return { ok: true, value: null };
  if (typeof v !== "object" || Array.isArray(v)) return { ok: false, value: null };
  const obj = v as Record<string, unknown>;
  const keys = Object.keys(obj);
  if (keys.length > MAX_FUNNEL_OUTCOME_KEYS) return { ok: false, value: null };
  for (const k of keys) {
    if (k.length > MAX_FUNNEL_SHORT_LEN) return { ok: false, value: null };
    const n = obj[k];
    if (typeof n !== "number" || !Number.isInteger(n) || n < 0) {
      return { ok: false, value: null };
    }
  }
  return { ok: true, value: JSON.stringify(obj) };
}

// Validate + normalize one funnel event into an insertable row, or null if
// malformed. Type-strict on every field; permissive about which fields a
// given event *name* carries (session-only fields are simply NULL on the
// other event types) so additive event types stay forward-compatible.
function parseFunnelEvent(raw: unknown): FunnelRow | null {
  if (!raw || typeof raw !== "object") return null;
  const e = raw as Record<string, unknown>;

  if (
    typeof e.event !== "string" ||
    e.event.length === 0 ||
    e.event.length > MAX_FUNNEL_SHORT_LEN
  ) {
    return null;
  }
  if (typeof e.instance_id !== "string" || !FUNNEL_INSTANCE_ID_RE.test(e.instance_id)) {
    return null;
  }
  if (typeof e.ts_hour !== "string" || e.ts_hour.length > 64) return null;
  const ts = parseTimestampHour(e.ts_hour);
  if (ts === null) return null;
  if (
    typeof e.library_version !== "string" ||
    e.library_version.length === 0 ||
    e.library_version.length > MAX_LIBRARY_VERSION_LEN
  ) {
    return null;
  }

  const python = optBoundedString(e.python, MAX_FUNNEL_SHORT_LEN);
  if (!python.ok) return null;
  const os = optBoundedString(e.os, MAX_FUNNEL_SHORT_LEN);
  if (!os.ok) return null;
  const adapter = optBoundedString(e.adapter, MAX_LABEL_LEN);
  if (!adapter.ok) return null;

  let sessionSeq: number | null = null;
  if (e.session_seq !== undefined && e.session_seq !== null) {
    if (typeof e.session_seq !== "number" || !Number.isInteger(e.session_seq) || e.session_seq < 0) {
      return null;
    }
    sessionSeq = e.session_seq;
  }

  const outcomes = parseFunnelOutcomes(e.outcomes);
  if (!outcomes.ok) return null;

  return {
    event: e.event,
    instance_id: e.instance_id,
    ts_hour: ts,
    library_version: e.library_version,
    python: python.value,
    os: os.value,
    adapter: adapter.value,
    session_seq: sessionSeq,
    outcomes: outcomes.value,
  };
}

// Validate the whole batch. The `library === "loopgain"` and
// `schema_version === 1` guards are what reject a misdirected product
// /v1/aggregate payload (which has neither an `events` array nor this
// library/schema combination) from landing in the funnel table.
function parseFunnelBatch(payload: unknown): { events: FunnelRow[] } | null {
  if (!payload || typeof payload !== "object") return null;
  const p = payload as Record<string, unknown>;
  if (p.schema_version !== FUNNEL_SCHEMA_VERSION) return null;
  if (p.library !== "loopgain") return null;
  if (!Array.isArray(p.events)) return null;
  if (p.events.length > MAX_FUNNEL_EVENTS) return null;

  const out: FunnelRow[] = [];
  for (const raw of p.events) {
    const row = parseFunnelEvent(raw);
    if (!row) return null;
    out.push(row);
  }
  return { events: out };
}

async function handleFunnel(request: Request, env: Env): Promise<Response> {
  if (request.method !== "POST") {
    return json({ error: "method_not_allowed" }, 405);
  }

  // Body-size cap. Fail fast before parsing JSON.
  const lenHeader = request.headers.get("Content-Length");
  if (lenHeader !== null) {
    const len = Number(lenHeader);
    if (!Number.isFinite(len) || len < 0 || len > MAX_FUNNEL_BODY_BYTES) {
      return json({ error: "payload_too_large" }, 413);
    }
  }

  let parsed: unknown;
  try {
    parsed = await request.json();
  } catch {
    return json({ error: "invalid_json" }, 400);
  }

  const batch = parseFunnelBatch(parsed);
  if (!batch) return json({ error: "invalid_payload" }, 400);

  // Insert one anonymous row per event. No customer_id, no IP — the table
  // has no column for either, by design.
  if (batch.events.length > 0) {
    const stmt = env.DB.prepare(
      `INSERT INTO funnel_events (
        event, instance_id, ts_hour, library_version,
        python, os, adapter, session_seq, outcomes
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    const statements = batch.events.map((e) =>
      stmt.bind(
        e.event,
        e.instance_id,
        e.ts_hour,
        e.library_version,
        e.python,
        e.os,
        e.adapter,
        e.session_seq,
        e.outcomes,
      ),
    );
    await env.DB.batch(statements);
  }

  return json({ status: "ok", accepted: batch.events.length }, 202);
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

// Row-LIMIT helper for the list endpoints. Default is high enough that a
// typical tenant gets every row in window; callers can override down (to
// reduce payload) or up to MAX_ROW_LIMIT. Previously the limits were
// hard-coded (500 on /v1/events, 1000 on /v1/profiles) which silently
// truncated the dashboard's view of any tenant with more activity than
// that — recency-biased and invisible to the UI. See Issue 1 in
// RECEIVER_ACCURACY_FIXES_KICKOFF.md.
const DEFAULT_ROW_LIMIT = 5000;
const MAX_ROW_LIMIT = 50000;
function parseRowLimit(url: URL): number {
  const raw = url.searchParams.get("limit");
  if (raw === null) return DEFAULT_ROW_LIMIT;
  const n = parseInt(raw, 10);
  if (!Number.isFinite(n) || n <= 0) return DEFAULT_ROW_LIMIT;
  return Math.min(n, MAX_ROW_LIMIT);
}

async function handleStats(request: Request, env: Env): Promise<Response> {
  if (request.method !== "GET") {
    return json({ error: "method_not_allowed" }, 405);
  }
  const customerId = await authenticate(request, env);
  if (!customerId) return json({ error: "unauthorized" }, 401);
  const rl = await env.READ_RL.limit({ key: customerId });
  if (!rl.success) return json({ error: "rate_limited" }, 429);
  return statsCore(env, customerId);
}

async function statsCore(env: Env, customerId: string): Promise<Response> {
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
            COALESCE(SUM(CASE WHEN rollback_triggered = 1 THEN 1 ELSE 0 END), 0) AS rollbacks,
            SUM(actual_dollars_saved) AS total_actual_dollars_saved,
            SUM(CASE WHEN actual_dollars_saved IS NOT NULL THEN 1 ELSE 0 END) AS event_count_with_actual_savings,
            SUM(actual_dollars_spent) AS total_actual_dollars_spent,
            SUM(CASE WHEN actual_dollars_spent IS NOT NULL THEN 1 ELSE 0 END) AS event_count_with_actual_spend
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
       LIMIT 5000`,
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

  // Tenant-wide aggregates of profile_max (Aβ proxy) and gain_margin.
  // Dashboards previously computed these client-side from /v1/events, but
  // that endpoint caps at LIMIT 500 ordered by timestamp DESC — a recency-
  // biased sample. Surfacing them here means a tenant with thousands of
  // events in window sees the real median, not a slice. SQLite/D1 has no
  // PERCENTILE_CONT, so each percentile is a small CTE: median uses the
  // standard "AVG of the two middle rows" trick (works for even+odd N);
  // p99 / p10 use "smallest row past the cutoff fraction".
  async function percentileAgg(column: "profile_max" | "gain_margin") {
    // Both columns exclude NULL rows: a NULL profile_max means the loop
    // converged at iter 1 (TARGET_MET) and never had Aβ measured, so it
    // shouldn't anchor the median. A NULL gain_margin means the metric
    // wasn't computable. The previous COALESCE(profile_max, 0.0) drove
    // ab_median to 0 for any tenant with a meaningful fraction of
    // TARGET_MET-at-iter-1 runs (see Issue 2 in
    // RECEIVER_ACCURACY_FIXES_KICKOFF.md). The right framing is
    // "median Aβ across runs that had measurable Aβ".
    const r = await env.DB.prepare(
      `WITH ordered AS (
         SELECT ${column} AS v,
                ROW_NUMBER() OVER (ORDER BY ${column}) AS rn,
                COUNT(*) OVER () AS total
           FROM loop_events
          WHERE customer_id = ? AND timestamp_hour >= ?
            AND ${column} IS NOT NULL
       )
       SELECT
         (SELECT AVG(v) FROM ordered WHERE rn IN ((total+1)/2, (total+2)/2)) AS median,
         (SELECT MIN(v) FROM ordered WHERE CAST(rn AS REAL)/total >= 0.99)  AS p99,
         (SELECT MIN(v) FROM ordered WHERE CAST(rn AS REAL)/total >= 0.10)  AS p10`,
    )
      .bind(customerId, since)
      .first<{ median: number | null; p99: number | null; p10: number | null }>();
    return r;
  }
  const [abAgg, gmAgg] = await Promise.all([
    percentileAgg("profile_max"),
    percentileAgg("gain_margin"),
  ]);

  // Per-outcome aggregates over the full window. The dashboard's Waste
  // "By outcome" breakdown previously extrapolated from the 500-row
  // /v1/events sample (recency-biased + truncated); these fleet-wide
  // sums let the panel render the real breakdown. iterations_avoided
  // is the sum of savings_vs_fixed_cap (iters not run vs the worst-case
  // fixed-cap baseline). actual_dollars_saved is summed only over rows
  // where the library shipped a paired-baseline measurement.
  const byOutcome = await env.DB.prepare(
    `SELECT outcome,
            COUNT(*) AS events,
            COALESCE(SUM(iterations_used), 0) AS iterations_used,
            COALESCE(SUM(savings_vs_fixed_cap), 0) AS iterations_avoided,
            SUM(actual_dollars_saved) AS actual_dollars_saved
       FROM loop_events
       WHERE customer_id = ? AND timestamp_hour >= ?
       GROUP BY outcome
       ORDER BY events DESC`,
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
    frameworks,
    loop_types: loopTypes,
    teams,
    // Tenant-wide percentile aggregates — see comment above.
    aggregates: {
      ab_median: abAgg?.median ?? null,
      ab_p99: abAgg?.p99 ?? null,
      gm_median: gmAgg?.median ?? null,
      gm_p10: gmAgg?.p10 ?? null,
      by_outcome: byOutcome.results,
    },
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
  return profilesCore(new URL(request.url), env, customerId);
}

async function profilesCore(
  url: URL,
  env: Env,
  customerId: string,
): Promise<Response> {
  const sinceParam = url.searchParams.get("since_hours");
  const since =
    Math.floor(Date.now() / 1000) -
    (sinceParam ? parseInt(sinceParam, 10) * 3600 : 30 * 24 * 3600);

  // workload_id is one of the classification filters; the helper applies it
  // along with framework/loop_type/team. id is included so the dashboard can
  // open Loop Detail without re-deriving from (workload_id, timestamp_hour).
  const filters = classificationFilters(url);
  const limit = parseRowLimit(url);
  const result = await env.DB.prepare(
    `SELECT id, timestamp_hour, workload_id, framework, loop_type, team,
            profile_min, profile_max, profile_median, profile_samples,
            outcome, iterations_used, gain_margin
       FROM loop_events
       WHERE customer_id = ? AND timestamp_hour >= ? ${filters.sql}
       ORDER BY timestamp_hour DESC
       LIMIT ?`,
  )
    .bind(customerId, since, ...filters.binds, limit)
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
  return eventsCore(new URL(request.url), env, customerId);
}

async function eventsCore(
  url: URL,
  env: Env,
  customerId: string,
): Promise<Response> {
  const rollbacksOnly = url.searchParams.get("rollbacks_only") === "true";
  const since = Math.floor(Date.now() / 1000) - 30 * 24 * 3600;

  const filters = classificationFilters(url);
  const rollbackClause = rollbacksOnly ? "AND rollback_triggered = 1" : "";
  const limit = parseRowLimit(url);
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
         LIMIT ?`,
    )
    .bind(customerId, since, ...filters.binds, limit)
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
  return calibrationCore(new URL(request.url), env, customerId);
}

async function calibrationCore(
  url: URL,
  env: Env,
  customerId: string,
): Promise<Response> {
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
  return eventDetailCore(env, customerId, idStr);
}

async function eventDetailCore(
  env: Env,
  customerId: string,
  idStr: string,
): Promise<Response> {
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
    funnel_schema_version: FUNNEL_SCHEMA_VERSION,
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

    // Public benchmark routes — no auth, wildcard CORS, edge-cacheable.
    // Routed BEFORE the per-IP AUTH_RL so legitimate dashboard polls of
    // /benchmark don't share the 60-rpm-per-IP authed-route bucket;
    // PUBLIC_RL handles abuse here independently.
    if (url.pathname.startsWith("/v1/public/benchmark/")) {
      if (request.method === "OPTIONS") {
        return new Response(null, {
          status: 204,
          headers: { ...BENCH_PUBLIC_HEADERS, "Cache-Control": BENCH_CACHE_OK },
        });
      }
      const resp = await handlePublicBenchmark(request, env, url);
      // Skip edge cache on empty / non-2xx responses so transient
      // zero-state doesn't get pinned for 5 minutes. handlePublicBenchmark
      // sets X-Bench-Empty: "1" on its empty-data path so we don't have to
      // re-parse the body here.
      const isOk = resp.status >= 200 && resp.status < 300;
      const isEmpty = resp.headers.get("X-Bench-Empty") === "1";
      const cache = isOk && !isEmpty ? BENCH_CACHE_OK : BENCH_CACHE_SKIP;
      const out = withHeaders(resp, { ...BENCH_PUBLIC_HEADERS, "Cache-Control": cache });
      out.headers.delete("X-Bench-Empty");
      return out;
    }

    // Anonymous funnel ingest — no auth, no bearer token, no CORS (it's a
    // server-to-server POST from the library's funnel module, like
    // /v1/aggregate). Routed BEFORE AUTH_RL so it uses its own per-IP bucket
    // (FUNNEL_RL) and never competes with the authed-route ceiling. The IP is
    // used here only as an ephemeral rate-limit key; it is NEVER stored —
    // funnel telemetry is anonymous and the table has no IP column.
    if (url.pathname === "/v1/funnel") {
      const fRl = await env.FUNNEL_RL.limit({ key: clientIp(request) });
      if (!fRl.success) return json({ error: "rate_limited" }, 429);
      return handleFunnel(request, env);
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
    return alertRulesListCore(env, customerId);
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

async function alertRulesListCore(
  env: Env,
  customerId: string,
): Promise<Response> {
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

async function handleAlertDeliveries(request: Request, env: Env): Promise<Response> {
  if (request.method !== "GET") return json({ error: "method_not_allowed" }, 405);
  const customerId = await authenticate(request, env);
  if (!customerId) return json({ error: "unauthorized" }, 401);
  const rl = await env.READ_RL.limit({ key: customerId });
  if (!rl.success) return json({ error: "rate_limited" }, 429);
  return alertDeliveriesCore(env, customerId);
}

async function alertDeliveriesCore(
  env: Env,
  customerId: string,
): Promise<Response> {
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

// ── Public benchmark routes ──────────────────────────────────────────
//
// Read-only, unauth'd mirrors of the /v1/* read endpoints, scoped to the
// hardcoded `BENCH_CUSTOMER_ID`. Rate-limited per IP via PUBLIC_RL;
// responses get 5-min edge cache + `Access-Control-Allow-Origin: *`.
// There is no parameter that selects a customer_id — the route family
// always serves the same canonical bench tenant.

async function handlePublicBenchmark(
  request: Request,
  env: Env,
  url: URL,
): Promise<Response> {
  if (request.method !== "GET") {
    return json({ error: "method_not_allowed" }, 405);
  }
  const rl = await env.PUBLIC_RL.limit({ key: clientIp(request) });
  if (!rl.success) return json({ error: "rate_limited" }, 429);

  const tail = url.pathname.slice("/v1/public/benchmark/".length);
  // Strip query string from the routing decision; tail compares the path only.
  let inner: Response;
  if (tail === "stats") inner = await statsCore(env, BENCH_CUSTOMER_ID);
  else if (tail === "profiles") inner = await profilesCore(url, env, BENCH_CUSTOMER_ID);
  else if (tail === "events") inner = await eventsCore(url, env, BENCH_CUSTOMER_ID);
  else if (tail === "calibration") inner = await calibrationCore(url, env, BENCH_CUSTOMER_ID);
  else if (tail === "alerts/rules") inner = await alertRulesListCore(env, BENCH_CUSTOMER_ID);
  else if (tail === "alerts/deliveries") inner = await alertDeliveriesCore(env, BENCH_CUSTOMER_ID);
  else if (tail.startsWith("event/")) {
    const idStr = tail.slice("event/".length);
    inner = await eventDetailCore(env, BENCH_CUSTOMER_ID, idStr);
  } else return json({ error: "not_found" }, 404);

  // Sniff the response body for empty/zero-state. We do this here (not
  // inside each core) so the authed path is untouched. Sentinel header is
  // stripped by the outer wrapper before the response leaves the worker.
  return await markIfEmpty(inner, tail);
}

/** Read the response body, decide if it's empty for caching purposes, and
 *  return a fresh Response with X-Bench-Empty set when appropriate. The
 *  outer caller maps that to Cache-Control: no-store so a transient zero-
 *  state response doesn't poison the edge cache for 5 minutes. */
async function markIfEmpty(resp: Response, tail: string): Promise<Response> {
  if (resp.status < 200 || resp.status >= 300) {
    return withHeaders(resp, { "X-Bench-Empty": "1" });
  }
  let isEmpty = false;
  let body: unknown;
  try {
    body = await resp.clone().json();
  } catch {
    body = null;
  }
  if (body && typeof body === "object") {
    const b = body as Record<string, unknown>;
    if (tail === "stats") {
      const totals = b.totals as { event_count?: number } | null;
      isEmpty = !totals || (totals.event_count ?? 0) === 0;
    } else if (tail === "profiles" || tail === "events" || tail === "calibration") {
      isEmpty = !Array.isArray(b.events) || (b.events as unknown[]).length === 0;
    } else if (tail === "alerts/rules") {
      isEmpty = !Array.isArray(b.rules) || (b.rules as unknown[]).length === 0;
    } else if (tail === "alerts/deliveries") {
      isEmpty = !Array.isArray(b.deliveries) || (b.deliveries as unknown[]).length === 0;
    }
  }
  return isEmpty ? withHeaders(resp, { "X-Bench-Empty": "1" }) : resp;
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
