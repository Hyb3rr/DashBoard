-- Phase 6A.1: raw local opportunity read model. No calibration or ranking.
CREATE TABLE IF NOT EXISTS market_local_opportunity (
  snapshot_id TEXT NOT NULL REFERENCES market_osm_snapshots(snapshot_id) ON DELETE CASCADE,
  country_code TEXT NOT NULL REFERENCES market_catalog(country_code),
  area_id TEXT,
  h3_cell_id TEXT NOT NULL,
  h3_resolution INTEGER NOT NULL,
  track TEXT NOT NULL,
  raw_local_score DOUBLE PRECISION,
  evidence_status TEXT NOT NULL,
  evidence_components JSONB NOT NULL DEFAULT '{}'::jsonb,
  coverage_fields JSONB NOT NULL DEFAULT '{}'::jsonb,
  model_version TEXT NOT NULL,
  missing_reason TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (snapshot_id, country_code, h3_cell_id, h3_resolution, track),
  CONSTRAINT market_local_track_check CHECK (track IN ('woodworking', 'metal_fabrication')),
  CONSTRAINT market_local_resolution_check CHECK (h3_resolution BETWEEN 0 AND 15),
  CONSTRAINT market_local_status_check CHECK (evidence_status IN ('scored', 'insufficient_local_evidence', 'unavailable', 'unknown')),
  CONSTRAINT market_local_score_status_check CHECK ((evidence_status = 'scored' AND raw_local_score IS NOT NULL) OR (evidence_status <> 'scored' AND raw_local_score IS NULL))
);

CREATE INDEX IF NOT EXISTS idx_market_local_current_query
  ON market_local_opportunity(country_code, track, h3_resolution, snapshot_id, evidence_status);
CREATE INDEX IF NOT EXISTS idx_market_local_area
  ON market_local_opportunity(area_id, track, h3_resolution);
