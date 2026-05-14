-- 0003_schema_v3.sql
-- Schema v3: per-iteration trajectories + classification fields.
--
-- Five additive columns on loop_events. Existing rows stay NULL (no backfill).
-- Library schema_version 3 (loopgain >= 0.1.6) starts populating them; v1
-- and v2 payloads continue to ingest with the new columns left NULL.
--
--   per_iteration_data — JSON {convergence_profile, error_history, truncated, cap}
--                        capped at 256 entries each, ~6 KB max per row.
--                        Powers the Loop Detail per-iteration scrubber.
--   framework, loop_type, team — opaque classification labels for filters.
--
-- Apply remote:  wrangler d1 execute loopgain-telemetry --file=./migrations/0003_schema_v3.sql --remote
-- Apply local:   wrangler d1 execute loopgain-telemetry --file=./migrations/0003_schema_v3.sql --local

ALTER TABLE loop_events ADD COLUMN per_iteration_data TEXT;
ALTER TABLE loop_events ADD COLUMN framework TEXT;
ALTER TABLE loop_events ADD COLUMN loop_type TEXT;
ALTER TABLE loop_events ADD COLUMN team TEXT;
