-- 0006_actual_dollars_spent.sql
-- Companion column to actual_dollars_saved (added in 0005). Captures the
-- real measured LG-side spend on a trial when the caller has cost data
-- per run (currently: the bench tenant, which has cost_usd.LG alongside
-- each B5/B10/B20 baseline cost). NULL for everyone else.
--
-- The dashboard prefers SUM(actual_dollars_spent) over the iter-count
-- × $/iter extrapolation when the column is populated, mirroring the
-- savings fallback. Together with actual_dollars_saved the Waste panel
-- can render fully-measured "saved + spent = would have spent" math
-- without the per-tenant string-match hack the dashboard carried
-- between 2026-05-25 and now.
--
-- Apply remote:  wrangler d1 execute loopgain-telemetry --file=./migrations/0006_actual_dollars_spent.sql --remote
-- Apply local:   wrangler d1 execute loopgain-telemetry --file=./migrations/0006_actual_dollars_spent.sql --local

ALTER TABLE loop_events ADD COLUMN actual_dollars_spent REAL DEFAULT NULL;
