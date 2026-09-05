-- LC-1A: persisted area-level opportunity read model.
-- Aggregation/calibration workers are intentionally deferred.
CREATE TABLE IF NOT EXISTS market_area_opportunity_summary (
  snapshot_id TEXT NOT NULL REFERENCES market_osm_snapshots(snapshot_id) ON DELETE CASCADE,
  country_code TEXT NOT NULL REFERENCES market_catalog(country_code),
  h3_resolution INTEGER NOT NULL,
  area_id TEXT NOT NULL REFERENCES market_areas(area_id),
  track TEXT NOT NULL,
  total_cells INTEGER NOT NULL DEFAULT 0,
  scored_cells INTEGER NOT NULL DEFAULT 0,
  evidence_coverage DOUBLE PRECISION NOT NULL DEFAULT 0,
  area_raw_score DOUBLE PRECISION,
  area_calibrated_score DOUBLE PRECISION,
  area_percentile DOUBLE PRECISION,
  evidence_status TEXT NOT NULL DEFAULT 'pending',
  missing_reason TEXT,
  model_version TEXT NOT NULL,
  calibration_version TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (snapshot_id,country_code,h3_resolution,area_id,track),
  CONSTRAINT market_area_summary_track_check CHECK (track IN ('woodworking','metal_fabrication')),
  CONSTRAINT market_area_summary_resolution_check CHECK (h3_resolution BETWEEN 0 AND 15),
  CONSTRAINT market_area_summary_counts_check CHECK (total_cells >= 0 AND scored_cells >= 0 AND scored_cells <= total_cells),
  CONSTRAINT market_area_summary_coverage_check CHECK (evidence_coverage BETWEEN 0 AND 1),
  CONSTRAINT market_area_summary_percentile_check CHECK (area_percentile IS NULL OR area_percentile BETWEEN 0 AND 1),
  CONSTRAINT market_area_summary_status_check CHECK (evidence_status IN ('pending','scored','insufficient_local_evidence')),
  CONSTRAINT market_area_summary_score_status_check CHECK (
    (evidence_status = 'scored' AND area_raw_score IS NOT NULL)
    OR (evidence_status <> 'scored' AND area_raw_score IS NULL)
  )
);

CREATE INDEX IF NOT EXISTS idx_market_area_summary_country_track
  ON market_area_opportunity_summary(country_code,track,h3_resolution,area_id);
CREATE INDEX IF NOT EXISTS idx_market_area_summary_rank
  ON market_area_opportunity_summary(country_code,track,area_raw_score DESC NULLS LAST);
