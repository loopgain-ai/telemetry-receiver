-- Migration 0008 — best_index (schema v3.4)
-- 0-based index of the lowest-error iteration. Powers the Iteration Waste view:
--   iterations-to-best   = best_index + 1
--   iterations-past-best = iterations_used - 1 - best_index
-- NULL on pre-v3.4 payloads.
ALTER TABLE loop_events ADD COLUMN best_index INTEGER;
