-- LC-2A.1: city-to-H3 spatial membership read model.
-- Rows are valid only for polygon geometry; centroid-only cities remain unsupported.
CREATE TABLE IF NOT EXISTS market_city_cell_membership (
  snapshot_id TEXT NOT NULL REFERENCES market_osm_snapshots(snapshot_id) ON DELETE CASCADE,
  country_code TEXT NOT NULL REFERENCES market_catalog(country_code),
  city_id TEXT NOT NULL REFERENCES market_areas(area_id) ON DELETE CASCADE,
  h3_cell_id TEXT NOT NULL,
  h3_resolution INTEGER NOT NULL,
  intersection_area DOUBLE PRECISION,
  membership_fraction DOUBLE PRECISION,
  geometry_source TEXT NOT NULL,
  geometry_version TEXT NOT NULL,
  membership_status TEXT NOT NULL DEFAULT 'ready',
  model_version TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (snapshot_id,country_code,city_id,h3_cell_id,h3_resolution),
  CONSTRAINT city_membership_resolution_check CHECK (h3_resolution BETWEEN 0 AND 15),
  CONSTRAINT city_membership_fraction_check CHECK (membership_fraction IS NULL OR (membership_fraction > 0 AND membership_fraction <= 1)),
  CONSTRAINT city_membership_status_check CHECK (membership_status IN ('ready','unsupported_geometry')),
  CONSTRAINT city_membership_ready_values_check CHECK (
    (membership_status = 'ready' AND intersection_area IS NOT NULL AND membership_fraction IS NOT NULL)
    OR membership_status = 'unsupported_geometry'
  )
);

CREATE INDEX IF NOT EXISTS idx_city_membership_country_city
  ON market_city_cell_membership(country_code,city_id,h3_resolution);
CREATE INDEX IF NOT EXISTS idx_city_membership_cell
  ON market_city_cell_membership(country_code,h3_cell_id,h3_resolution);
