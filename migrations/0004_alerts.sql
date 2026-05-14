-- 0004_alerts.sql
-- Alert subsystem: customer-defined rules evaluated by a scheduled cron
-- handler, with delivery audit trail.
--
--   alert_rules       — per-customer rules. predicate + filter stored as
--                       JSON for forward compatibility (new predicate types
--                       don't require schema changes).
--   alert_deliveries  — append-only audit log of every fire/skip/failure.
--
-- Apply remote:  wrangler d1 execute loopgain-telemetry --file=./migrations/0004_alerts.sql --remote
-- Apply local:   wrangler d1 execute loopgain-telemetry --file=./migrations/0004_alerts.sql --local

CREATE TABLE IF NOT EXISTS alert_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_id TEXT NOT NULL,
    name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    -- Predicate JSON, e.g. {"metric":"outcome_count","outcome":"diverged",
    -- "operator":">","threshold":3}
    predicate TEXT NOT NULL,
    -- Filter JSON, e.g. {"workload_id":"rag-rewrite-A","framework":"langgraph"}
    -- All keys optional; null/absent = match anything.
    filter TEXT,
    window_seconds INTEGER NOT NULL,
    cooldown_seconds INTEGER NOT NULL DEFAULT 600,
    -- Action: webhook only in v1. action_secret is reserved for future
    -- HMAC signing; not used in v1 webhook delivery.
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

-- Partial index for the cron handler: only enabled rules need evaluation.
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
    -- 'sent' (2xx), 'failed' (non-2xx or network), 'skipped_cooldown',
    -- 'skipped_disabled' (rule disabled mid-evaluation).
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
