-- 0002_eta_calibration.sql
-- Schema v2: add first-eta-prediction snapshot for the ETA Accuracy panel.
--
-- Two additive columns on loop_events. Existing rows stay NULL (no backfill).
-- Library schema_version 2 (loopgain >= 0.1.4) starts populating them;
-- v1 payloads continue to ingest with both columns left NULL.
--
-- Apply remote:  wrangler d1 execute loopgain-telemetry --file=./migrations/0002_eta_calibration.sql --remote
-- Apply local:   wrangler d1 execute loopgain-telemetry --file=./migrations/0002_eta_calibration.sql --local

ALTER TABLE loop_events ADD COLUMN first_eta_prediction INTEGER;
ALTER TABLE loop_events ADD COLUMN first_eta_at_iteration INTEGER;

-- Index optimized for the calibration endpoint: pulls converged events
-- with a non-NULL prediction, ordered by time. Partial index keeps it
-- small (only ~the slice of rows the panel actually queries).
CREATE INDEX IF NOT EXISTS idx_loop_events_calibration
    ON loop_events (customer_id, timestamp_hour DESC)
    WHERE outcome = 'converged' AND first_eta_prediction IS NOT NULL;
