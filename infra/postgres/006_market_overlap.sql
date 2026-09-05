-- Phase 7A: directional overlap / whitespace read model.
-- Computation is intentionally deferred to Phase 7B.
CREATE TABLE IF NOT EXISTS market_area_overlap (
  snapshot_id TEXT NOT NULL REFERENCES market_osm_snapshots(snapshot_id) ON DELETE CASCADE,
  country_code TEXT NOT NULL REFERENCES market_catalog(country_code),
  h3_resolution INTEGER NOT NULL,
  track TEXT NOT NULL,
  area_id_a TEXT NOT NULL REFERENCES market_areas(area_id),
  area_id_b TEXT NOT NULL REFERENCES market_areas(area_id),
  shared_opportunity DOUBLE PRECISION NOT NULL DEFAULT 0,
  opportunity_a DOUBLE PRECISION NOT NULL DEFAULT 0,
  opportunity_b DOUBLE PRECISION NOT NULL DEFAULT 0,
  overlap_a_to_b DOUBLE PRECISION NOT NULL DEFAULT 0,
  overlap_b_to_a DOUBLE PRECISION NOT NULL DEFAULT 0,
  remaining_opportunity_a DOUBLE PRECISION NOT NULL DEFAULT 0,
  remaining_opportunity_b DOUBLE PRECISION NOT NULL DEFAULT 0,
  calculation_version TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (snapshot_id,country_code,h3_resolution,track,area_id_a,area_id_b),
  CONSTRAINT market_overlap_track_check CHECK (track IN ('woodworking','metal_fabrication')),
  CONSTRAINT market_overlap_resolution_check CHECK (h3_resolution BETWEEN 0 AND 15),
  CONSTRAINT market_overlap_distinct_areas_check CHECK (area_id_a <> area_id_b),
  CONSTRAINT market_overlap_nonnegative_check CHECK (
    shared_opportunity >= 0 AND opportunity_a >= 0 AND opportunity_b >= 0 AND
    remaining_opportunity_a >= 0 AND remaining_opportunity_b >= 0
  ),
  CONSTRAINT market_overlap_ratio_check CHECK (
    overlap_a_to_b BETWEEN 0 AND 1 AND overlap_b_to_a BETWEEN 0 AND 1
  )
);

CREATE INDEX IF NOT EXISTS idx_market_overlap_area_a
  ON market_area_overlap(area_id_a,track,h3_resolution,snapshot_id);
CREATE INDEX IF NOT EXISTS idx_market_overlap_area_b
  ON market_area_overlap(area_id_b,track,h3_resolution,snapshot_id);
