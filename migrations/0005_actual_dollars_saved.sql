-- 0005_actual_dollars_saved.sql
-- Additive column for tenants that can ship a real paired-baseline dollar
-- delta per trial (currently: the bench tenant, which has B5/B10/B20
-- baseline costs alongside each LG run). NULL for everyone else.
--
-- Aggregation queries sum non-NULL rows; the dashboard prefers
-- SUM(actual_dollars_saved) over the iter-extrapolation heuristic when
-- the column is populated.
--
-- Apply remote:  wrangler d1 execute loopgain-telemetry --file=./migrations/0005_actual_dollars_saved.sql --remote
-- Apply local:   wrangler d1 execute loopgain-telemetry --file=./migrations/0005_actual_dollars_saved.sql --local

ALTER TABLE loop_events ADD COLUMN actual_dollars_saved REAL DEFAULT NULL;
