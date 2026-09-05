-- Independent of mutable rules and delivery history. No client CRUD path.
CREATE TABLE IF NOT EXISTS email_quota_reservations (
    id TEXT PRIMARY KEY NOT NULL,
    customer_id TEXT NOT NULL,
    reserved_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_email_quota_customer_time
    ON email_quota_reservations (customer_id, reserved_at);

-- Old history has no immutable channel. Conservatively count all successful
-- deliveries from the last day; rule changes cannot hide retained history.
INSERT OR IGNORE INTO email_quota_reservations (id, customer_id, reserved_at)
SELECT 'legacy-delivery-' || id, customer_id, fired_at FROM alert_deliveries
WHERE fired_at >= unixepoch() - 86400
  AND delivery_status IN ('sent', 'test_sent');
