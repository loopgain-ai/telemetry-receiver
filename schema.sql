-- LoopGain telemetry receiver D1 schema.
-- Apply via: wrangler d1 execute loopgain-telemetry --file=./schema.sql --remote
-- (Use --local instead of --remote for local development.)

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
    received_at INTEGER NOT NULL DEFAULT (unixepoch()),
    FOREIGN KEY (customer_id) REFERENCES customers(customer_id)
);

CREATE INDEX IF NOT EXISTS idx_loop_events_customer_time
    ON loop_events (customer_id, timestamp_hour DESC);

CREATE INDEX IF NOT EXISTS idx_loop_events_customer_workload_time
    ON loop_events (customer_id, workload_id, timestamp_hour DESC);

CREATE INDEX IF NOT EXISTS idx_loop_events_rollbacks
    ON loop_events (customer_id, rollback_triggered, timestamp_hour DESC);
