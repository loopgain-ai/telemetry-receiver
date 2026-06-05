-- LoopGain telemetry receiver D1 schema (v3).
--
-- Fresh deploys: apply this file. Existing deploys: apply the migration
-- under migrations/ instead.
--
-- Apply via: wrangler d1 execute loopgain-telemetry --file=./schema.sql --remote
-- (Use --local instead of --remote for local development.)
--
-- Schema versions:
--   v1 (2026-05-12) — initial release.
--   v2 (2026-05-13) — added first_eta_prediction + first_eta_at_iteration
--                     for the ETA Accuracy dashboard panel.
--   v3 (2026-05-14) — added per_iteration_data (JSON, capped at 256 entries)
--                     for the Loop Detail scrubber, plus framework/loop_type/
--                     team classification columns for dashboard filters.
--   v3.1 (2026-05-25) — added actual_dollars_saved (REAL, nullable) for
--                       tenants with paired-baseline cost data (bench).
--   v3.2 (2026-05-26) — added actual_dollars_spent (REAL, nullable),
--                       companion to actual_dollars_saved. Together they
--                       drive the Waste panel's fully-measured math
--                       without per-tenant special-casing in the dashboard.
--   v3.3 (2026-05-30) — added the funnel_events table for ANONYMOUS,
--                       unauthenticated adoption-funnel telemetry from the
--                       OSS library's loopgain.funnel module (POST /v1/funnel).
--                       Entirely separate from loop_events: no customer_id,
--                       no bearer token, no IP. See migration 0007.

-- Customers and their bearer tokens.
-- token_hash is the SHA-256 hex digest of the bearer token. The plain token
-- is shown to the customer once at provisioning and then never persisted.
CREATE TABLE IF NOT EXISTS customers (
    customer_id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    name TEXT,
    contact_email TEXT,
    created_at INTEGER NOT NULL,
    last_seen_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_customers_token_hash
    ON customers (token_hash);

-- One row per loop run. Immutable, append-only.
CREATE TABLE IF NOT EXISTS loop_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_id TEXT NOT NULL,
    workload_id TEXT,
    timestamp_hour INTEGER NOT NULL,        -- unix seconds, hour-bucketed
    library_version TEXT NOT NULL,
    outcome TEXT NOT NULL,                  -- "converged" | "oscillating" | "diverged" | "max_iterations" | ...
    iterations_used INTEGER NOT NULL,
    gain_margin REAL,
    savings_vs_fixed_cap INTEGER,
    rollback_triggered INTEGER NOT NULL,    -- 0 or 1
    profile_min REAL,
    profile_max REAL,
    profile_median REAL,
    profile_samples INTEGER,
    threshold_fast_converge REAL NOT NULL,
    threshold_converging REAL NOT NULL,
    threshold_stalling REAL NOT NULL,
    threshold_oscillating_upper REAL NOT NULL,
    smoothing_window INTEGER NOT NULL,
    -- v2: first non-NULL eta snapshot captured during the loop, plus the
    -- iteration count when it was captured. Used by the ETA Accuracy panel
    -- to plot predicted vs. actual iterations-to-converge. NULL on v1
    -- payloads and on loops where no prediction was ever computable
    -- (target_error=0, never-converging traces, etc.).
    first_eta_prediction INTEGER,
    first_eta_at_iteration INTEGER,
    -- v3: per-iteration trajectories serialized as JSON
    -- {convergence_profile: number[], error_history: number[],
    --  truncated: boolean, cap: number}. Capped at 256 entries each in the
    -- library before transmission, ~6 KB max. NULL on v1/v2 payloads or
    -- when the library was asked to omit per-iteration data.
    per_iteration_data TEXT,
    -- v3: optional classification labels. Free-form opaque strings used
    -- for filtering in the dashboard. framework is typically auto-stamped
    -- by integration adapters ("langgraph", "crewai", etc.).
    framework TEXT,
    loop_type TEXT,
    team TEXT,
    -- v3.1: actual measured $ saved on this trial, populated only by
    -- tenants with paired-baseline cost data (currently: the bench).
    -- Real customers leave this NULL and the dashboard falls back to
    -- iter-count × $/iter extrapolation.
    actual_dollars_saved REAL,
    -- v3.2: actual measured $ spent on this trial (the LG-side cost).
    -- Same population semantics as actual_dollars_saved — populated by
    -- tenants with real per-run cost data, NULL otherwise. Lets the
    -- Waste panel show measured spend alongside measured savings instead
    -- of falling back to iter × $/iter extrapolation.
    actual_dollars_spent REAL,
    -- v3.4: 0-based index of the lowest-error iteration. Drives the Iteration
    -- Waste view: iterations-to-best = best_index+1, iterations-past-best =
    -- iterations_used-1-best_index. NULL on pre-v3.4 payloads.
    best_index INTEGER,
    received_at INTEGER NOT NULL DEFAULT (unixepoch()),
    FOREIGN KEY (customer_id) REFERENCES customers(customer_id)
);

CREATE INDEX IF NOT EXISTS idx_loop_events_customer_time
    ON loop_events (customer_id, timestamp_hour DESC);

CREATE INDEX IF NOT EXISTS idx_loop_events_customer_workload_time
    ON loop_events (customer_id, workload_id, timestamp_hour DESC);

CREATE INDEX IF NOT EXISTS idx_loop_events_rollbacks
    ON loop_events (customer_id, rollback_triggered, timestamp_hour DESC);

-- Partial index for the ETA Accuracy panel: only the rows the calibration
-- query touches.
CREATE INDEX IF NOT EXISTS idx_loop_events_calibration
    ON loop_events (customer_id, timestamp_hour DESC)
    WHERE outcome = 'converged' AND first_eta_prediction IS NOT NULL;

-- ── Alerting (schema v3+) ─────────────────────────────────────────────
--
-- Customer-defined rules evaluated by a scheduled cron handler, with
-- delivery audit trail. Predicate and filter are JSON for forward
-- compatibility (new predicate types don't require migrations).

CREATE TABLE IF NOT EXISTS alert_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_id TEXT NOT NULL,
    name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    predicate TEXT NOT NULL,
    filter TEXT,
    window_seconds INTEGER NOT NULL,
    cooldown_seconds INTEGER NOT NULL DEFAULT 600,
    action_type TEXT NOT NULL,
    action_url TEXT NOT NULL,
    action_secret TEXT,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
    last_fired_at INTEGER,
    FOREIGN KEY (customer_id) REFERENCES customers(customer_id)
);

CREATE INDEX IF NOT EXISTS idx_alert_rules_customer
    ON alert_rules (customer_id);

CREATE INDEX IF NOT EXISTS idx_alert_rules_enabled
    ON alert_rules (enabled, last_fired_at)
    WHERE enabled = 1;

CREATE TABLE IF NOT EXISTS alert_deliveries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id INTEGER NOT NULL,
    customer_id TEXT NOT NULL,
    fired_at INTEGER NOT NULL,
    match_value REAL NOT NULL,
    match_count INTEGER NOT NULL,
    delivery_status TEXT NOT NULL,
    delivery_status_code INTEGER,
    delivery_error TEXT,
    FOREIGN KEY (rule_id) REFERENCES alert_rules(id),
    FOREIGN KEY (customer_id) REFERENCES customers(customer_id)
);

CREATE INDEX IF NOT EXISTS idx_alert_deliveries_customer_time
    ON alert_deliveries (customer_id, fired_at DESC);

CREATE INDEX IF NOT EXISTS idx_alert_deliveries_rule_time
    ON alert_deliveries (rule_id, fired_at DESC);

-- ── Funnel telemetry (schema v3.3+) ───────────────────────────────────
--
-- ANONYMOUS, unauthenticated adoption-funnel events from the open-source
-- library's `loopgain.funnel` module (POST /v1/funnel). This is a wholly
-- separate path from loop_events above:
--   - There is NO customer_id and NO bearer token — the data is anonymous.
--   - There is NO IP column. Client IPs are never stored (the privacy
--     contract in loopgain-core/TELEMETRY.md says IPs are never collected).
--   - instance_id is a locally-generated random uuid4().hex — not derived
--     from any hardware/user/network identifier — and exists only to avoid
--     counting one install as many.
-- Rows answer one question: install (first_init) → activate (first_observe)
-- → retain (recurring session events), across the OSS userbase.
CREATE TABLE IF NOT EXISTS funnel_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event TEXT NOT NULL,            -- "first_init" | "first_observe" | "session"
    instance_id TEXT NOT NULL,      -- random uuid4().hex (anonymous, 32 hex)
    ts_hour INTEGER NOT NULL,       -- unix seconds, hour-bucketed
    library_version TEXT NOT NULL,
    python TEXT,                    -- "3.12" etc. (major.minor only)
    os TEXT,                        -- "Darwin" | "Linux" | "Windows"
    adapter TEXT,                   -- session events only; "langgraph" etc. or NULL
    session_seq INTEGER,            -- session events only; the install's session counter
    outcomes TEXT,                  -- session events only; JSON coarse outcome counts
    received_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- Count events of a type over time (install/activate/retain curves).
CREATE INDEX IF NOT EXISTS idx_funnel_events_event_ts
    ON funnel_events (event, ts_hour DESC);

-- Group an install's events together (per-install funnel + retention).
CREATE INDEX IF NOT EXISTS idx_funnel_events_instance
    ON funnel_events (instance_id);
