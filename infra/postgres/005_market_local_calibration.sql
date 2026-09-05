-- Phase 6B.4-A: calibration persistence foundation.
-- Values remain NULL until a validated method is selected per track.
ALTER TABLE market_local_opportunity
  ADD COLUMN IF NOT EXISTS calibrated_score DOUBLE PRECISION,
  ADD COLUMN IF NOT EXISTS peer_percentile DOUBLE PRECISION,
  ADD COLUMN IF NOT EXISTS calibration_method TEXT,
  ADD COLUMN IF NOT EXISTS calibration_version TEXT,
  ADD COLUMN IF NOT EXISTS calibration_status TEXT NOT NULL DEFAULT 'not_selected';

CREATE INDEX IF NOT EXISTS idx_market_local_calibration
  ON market_local_opportunity(country_code, track, calibration_status, calibration_version);
