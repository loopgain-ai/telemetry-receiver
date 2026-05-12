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
 *   GET  /v1/stats          Aggregated stats for the bearer's customer (30d).
 *   GET  /v1/profiles       Convergence-profile events (optionally per-workload).
 *   GET  /v1/events         Recent loop events for the rollback log.
 *   GET  /health            Liveness probe.
 */

export interface Env {
  DB: D1Database;
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
  };
  thresholds: {
    fast_converge: number;
    converging: number;
    stalling: number;
    oscillating_upper: number;
  };
  smoothing_window: number;
}

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Authorization, Content-Type",
};

function json(body: unknown, status = 200, extraHeaders: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...CORS_HEADERS, ...extraHeaders },
  });
}

async function sha256(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function authenticate(request: Request, env: Env): Promise<string | null> {
  const auth = request.headers.get("Authorization");
  if (!auth || !auth.startsWith("Bearer ")) return null;
  const token = auth.slice(7).trim();
  if (!token) return null;

  const tokenHash = await sha256(token);
  const row = await env.DB.prepare(
    "SELECT customer_id FROM customers WHERE token_hash = ?"
  )
    .bind(tokenHash)
    .first<{ customer_id: string }>();

  return row?.customer_id ?? null;
}

function parseTimestampHour(iso: string): number | null {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  return Math.floor(d.getTime() / 1000);
}

function validatePayload(payload: unknown): payload is TelemetryPayload {
  if (!payload || typeof payload !== "object") return false;
  const p = payload as Partial<TelemetryPayload>;
  if (p.schema_version !== 1) return false;
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
  return true;
}

async function handleAggregate(request: Request, env: Env): Promise<Response> {
  if (request.method !== "POST") {
    return json({ error: "method_not_allowed" }, 405);
  }

  const customerId = await authenticate(request, env);
  if (!customerId) return json({ error: "unauthorized" }, 401);

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

  const now = Math.floor(Date.now() / 1000);
  const summary = payload.loop.convergence_profile_summary;

  await env.DB.prepare(
    `INSERT INTO loop_events (
      customer_id, workload_id, timestamp_hour, library_version,
      outcome, iterations_used, gain_margin, savings_vs_fixed_cap,
      rollback_triggered, profile_min, profile_max, profile_median,
      profile_samples, threshold_fast_converge, threshold_converging,
      threshold_stalling, threshold_oscillating_upper,
      smoothing_window, received_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
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
      payload.smoothing_window
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

  const since = Math.floor(Date.now() / 1000) - 30 * 24 * 3600;

  const outcomeStats = await env.DB.prepare(
    `SELECT outcome, COUNT(*) AS count
       FROM loop_events
       WHERE customer_id = ? AND timestamp_hour >= ?
       GROUP BY outcome`
  )
    .bind(customerId, since)
    .all();

  const totals = await env.DB.prepare(
    `SELECT COUNT(*) AS event_count,
            COALESCE(SUM(iterations_used), 0) AS total_iterations,
            COALESCE(SUM(savings_vs_fixed_cap), 0) AS total_savings,
            COALESCE(SUM(CASE WHEN rollback_triggered = 1 THEN 1 ELSE 0 END), 0) AS rollbacks
       FROM loop_events
       WHERE customer_id = ? AND timestamp_hour >= ?`
  )
    .bind(customerId, since)
    .first();

  const workloadStats = await env.DB.prepare(
    `SELECT workload_id, COUNT(*) AS count
       FROM loop_events
       WHERE customer_id = ? AND timestamp_hour >= ?
       GROUP BY workload_id
       ORDER BY count DESC
       LIMIT 50`
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

  const url = new URL(request.url);
  const rollbacksOnly = url.searchParams.get("rollbacks_only") === "true";
  const since = Math.floor(Date.now() / 1000) - 30 * 24 * 3600;

  const query = rollbacksOnly
    ? `SELECT timestamp_hour, workload_id, outcome, iterations_used,
              gain_margin, profile_max, savings_vs_fixed_cap, library_version
         FROM loop_events
         WHERE customer_id = ? AND timestamp_hour >= ? AND rollback_triggered = 1
         ORDER BY timestamp_hour DESC
         LIMIT 500`
    : `SELECT timestamp_hour, workload_id, outcome, iterations_used,
              gain_margin, profile_max, savings_vs_fixed_cap, library_version
         FROM loop_events
         WHERE customer_id = ? AND timestamp_hour >= ?
         ORDER BY timestamp_hour DESC
         LIMIT 500`;

  const result = await env.DB.prepare(query).bind(customerId, since).all();
  return json({ customer_id: customerId, events: result.results });
}

async function handleHealth(): Promise<Response> {
  return json({ status: "ok", schema_version: 1, service: "loopgain-telemetry-receiver" });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    const url = new URL(request.url);
    switch (url.pathname) {
      case "/v1/aggregate":
        return handleAggregate(request, env);
      case "/v1/stats":
        return handleStats(request, env);
      case "/v1/profiles":
        return handleProfiles(request, env);
      case "/v1/events":
        return handleEvents(request, env);
      case "/health":
      case "/":
        return handleHealth();
      default:
        return json({ error: "not_found" }, 404);
    }
  },
};
