-- 0007_funnel.sql
-- Adds the funnel_events table for ANONYMOUS, unauthenticated adoption-funnel
-- telemetry from the open-source library's `loopgain.funnel` module
-- (POST /v1/funnel). This is a wholly separate ingest path from loop_events:
--   - NO customer_id, NO bearer token — the data is anonymous.
--   - NO IP column. Client IPs are never stored (privacy contract in
--     loopgain-core/TELEMETRY.md: IPs are never collected). The IP is used
--     only as an ephemeral per-IP rate-limit key in the Worker.
--   - instance_id is a locally-generated random uuid4().hex — not derived
--     from any hardware/user/network identifier.
-- Rows answer one question: install (first_init) → activate (first_observe)
-- → retain (recurring session events), across the OSS userbase.
--
-- Apply remote:  wrangler d1 execute loopgain-telemetry --file=./migrations/0007_funnel.sql --remote
-- Apply local:   wrangler d1 execute loopgain-telemetry --file=./migrations/0007_funnel.sql --local

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

CREATE INDEX IF NOT EXISTS idx_funnel_events_event_ts
    ON funnel_events (event, ts_hour DESC);

CREATE INDEX IF NOT EXISTS idx_funnel_events_instance
    ON funnel_events (instance_id);
