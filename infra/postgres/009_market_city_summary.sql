-- LC-2B.1: city/urban-centre opportunity summary read model.
CREATE TABLE IF NOT EXISTS market_city_opportunity_summary (
  snapshot_id TEXT NOT NULL REFERENCES market_osm_snapshots(snapshot_id) ON DELETE CASCADE,
  country_code TEXT NOT NULL REFERENCES market_catalog(country_code),
  city_id TEXT NOT NULL REFERENCES market_areas(area_id) ON DELETE CASCADE,
  track TEXT NOT NULL,
  total_cells INTEGER NOT NULL DEFAULT 0,
  scored_cells INTEGER NOT NULL DEFAULT 0,
  membership_weight DOUBLE PRECISION NOT NULL DEFAULT 0,
  scored_membership_weight DOUBLE PRECISION NOT NULL DEFAULT 0,
  evidence_coverage DOUBLE PRECISION NOT NULL DEFAULT 0,
  city_raw_score DOUBLE PRECISION,
  city_calibrated_score DOUBLE PRECISION,
  city_percentile DOUBLE PRECISION,
  evidence_status TEXT NOT NULL DEFAULT 'pending',
  missing_reason TEXT,
  geometry_source TEXT NOT NULL,
  model_version TEXT NOT NULL,
  calibration_version TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (snapshot_id,country_code,city_id,track),
  CONSTRAINT city_summary_track_check CHECK (track IN ('woodworking','metal_fabrication')),
  CONSTRAINT city_summary_counts_check CHECK (total_cells >= 0 AND scored_cells >= 0 AND scored_cells <= total_cells),
  CONSTRAINT city_summary_weights_check CHECK (membership_weight >= 0 AND scored_membership_weight >= 0 AND scored_membership_weight <= membership_weight),
  CONSTRAINT city_summary_coverage_check CHECK (evidence_coverage BETWEEN 0 AND 1),
  CONSTRAINT city_summary_percentile_check CHECK (city_percentile IS NULL OR city_percentile BETWEEN 0 AND 1),
  CONSTRAINT city_summary_status_check CHECK (evidence_status IN ('pending','scored','insufficient_local_evidence')),
  CONSTRAINT city_summary_score_status_check CHECK ((evidence_status = 'scored' AND city_raw_score IS NOT NULL) OR (evidence_status <> 'scored' AND city_raw_score IS NULL))
);
CREATE INDEX IF NOT EXISTS idx_city_summary_country_track ON market_city_opportunity_summary(country_code,track,city_id);
CREATE INDEX IF NOT EXISTS idx_city_summary_rank ON market_city_opportunity_summary(country_code,track,city_raw_score DESC NULLS LAST);
