CREATE TABLE IF NOT EXISTS market_catalog (
  country_code TEXT PRIMARY KEY,
  country_name TEXT NOT NULL,
  iso3_code TEXT,
  un_member BOOLEAN NOT NULL DEFAULT FALSE,
  primary_market BOOLEAN NOT NULL DEFAULT FALSE,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_market_catalog_primary_active
  ON market_catalog(primary_market, active);

CREATE TABLE IF NOT EXISTS market_areas (
  area_id TEXT PRIMARY KEY,
  country_code TEXT NOT NULL REFERENCES market_catalog(country_code),
  name TEXT NOT NULL,
  area_type TEXT NOT NULL,
  admin_level INTEGER,
  granularity_class TEXT NOT NULL DEFAULT 'unknown',
  parent_area_id TEXT REFERENCES market_areas(area_id),
  source TEXT NOT NULL,
  source_id TEXT NOT NULL,
  centroid_lat DOUBLE PRECISION,
  centroid_lon DOUBLE PRECISION,
  bbox_min_lat DOUBLE PRECISION,
  bbox_min_lon DOUBLE PRECISION,
  bbox_max_lat DOUBLE PRECISION,
  bbox_max_lon DOUBLE PRECISION,
  geometry_ref JSONB NOT NULL DEFAULT '{}'::jsonb,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT market_areas_type_check CHECK (area_type IN ('city', 'administrative_area', 'industrial_cluster')),
  CONSTRAINT market_areas_granularity_check CHECK (granularity_class IN ('unknown', 'normal', 'coarse', 'degenerate')),
  CONSTRAINT market_areas_admin_level_check CHECK (admin_level IS NULL OR admin_level >= 0),
  CONSTRAINT market_areas_source_identity UNIQUE (source, source_id, country_code)
);

CREATE INDEX IF NOT EXISTS idx_market_areas_country_type_active
  ON market_areas(country_code, area_type, active);
CREATE INDEX IF NOT EXISTS idx_market_areas_parent
  ON market_areas(parent_area_id);

CREATE TABLE IF NOT EXISTS market_area_sources (
  area_id TEXT NOT NULL REFERENCES market_areas(area_id) ON DELETE CASCADE,
  source_name TEXT NOT NULL,
  source_object_id TEXT NOT NULL,
  source_version TEXT,
  source_confidence INTEGER,
  last_checked_at TIMESTAMPTZ,
  last_success_at TIMESTAMPTZ,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  PRIMARY KEY (area_id, source_name, source_object_id),
  CONSTRAINT market_area_sources_confidence_check CHECK (source_confidence IS NULL OR source_confidence BETWEEN 0 AND 100)
);

CREATE TABLE IF NOT EXISTS market_job_state (
  job_key TEXT PRIMARY KEY,
  source TEXT NOT NULL,
  country_code TEXT REFERENCES market_catalog(country_code),
  status TEXT NOT NULL DEFAULT 'pending',
  current_step TEXT,
  source_version TEXT,
  source_hash TEXT,
  retry_count INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  started_at TIMESTAMPTZ,
  last_heartbeat_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at TIMESTAMPTZ,
  CONSTRAINT market_job_state_retry_check CHECK (retry_count >= 0)
);

CREATE INDEX IF NOT EXISTS idx_market_job_state_status_source
  ON market_job_state(status, source);
CREATE INDEX IF NOT EXISTS idx_market_job_state_country
  ON market_job_state(country_code);

CREATE TABLE IF NOT EXISTS market_osm_snapshots (
  snapshot_id TEXT PRIMARY KEY,
  country_code TEXT NOT NULL REFERENCES market_catalog(country_code),
  source_url TEXT NOT NULL,
  source_version TEXT NOT NULL,
  source_hash TEXT NOT NULL,
  filter_version TEXT NOT NULL,
  classification_version TEXT NOT NULL,
  h3_resolution INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'staging',
  active BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  activated_at TIMESTAMPTZ,
  CONSTRAINT market_osm_snapshot_status_check CHECK (status IN ('staging', 'active', 'superseded', 'failed')),
  CONSTRAINT market_osm_snapshot_resolution_check CHECK (h3_resolution BETWEEN 0 AND 15),
  CONSTRAINT market_osm_snapshot_identity UNIQUE (country_code, source_hash, classification_version, h3_resolution)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_market_osm_one_active_country
  ON market_osm_snapshots(country_code) WHERE active;
CREATE INDEX IF NOT EXISTS idx_market_osm_snapshot_country_status
  ON market_osm_snapshots(country_code, status);

CREATE TABLE IF NOT EXISTS market_cell_features (
  snapshot_id TEXT NOT NULL REFERENCES market_osm_snapshots(snapshot_id) ON DELETE CASCADE,
  country_code TEXT NOT NULL REFERENCES market_catalog(country_code),
  h3_cell_id TEXT NOT NULL,
  h3_resolution INTEGER NOT NULL,
  track TEXT NOT NULL,
  source TEXT NOT NULL,
  source_version TEXT NOT NULL,
  classification_version TEXT NOT NULL,
  industrial_area_count INTEGER NOT NULL DEFAULT 0,
  works_count INTEGER NOT NULL DEFAULT 0,
  sawmill_count INTEGER NOT NULL DEFAULT 0,
  furniture_evidence_count INTEGER NOT NULL DEFAULT 0,
  wood_processing_count INTEGER NOT NULL DEFAULT 0,
  metal_evidence_count INTEGER NOT NULL DEFAULT 0,
  machinery_evidence_count INTEGER NOT NULL DEFAULT 0,
  osm_feature_count INTEGER NOT NULL DEFAULT 0,
  osm_last_observed TIMESTAMPTZ,
  osm_feature_density DOUBLE PRECISION,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (snapshot_id, country_code, h3_cell_id, h3_resolution, track),
  CONSTRAINT market_cell_feature_track_check CHECK (track IN ('woodworking', 'metal_fabrication')),
  CONSTRAINT market_cell_feature_resolution_check CHECK (h3_resolution BETWEEN 0 AND 15)
);

CREATE INDEX IF NOT EXISTS idx_market_cell_features_current_query
  ON market_cell_features(country_code, track, h3_resolution, snapshot_id);
CREATE INDEX IF NOT EXISTS idx_market_cell_features_cell
  ON market_cell_features(h3_cell_id, h3_resolution);

CREATE TABLE IF NOT EXISTS market_opportunity_cells (
  snapshot_id TEXT NOT NULL REFERENCES market_osm_snapshots(snapshot_id) ON DELETE CASCADE,
  country_code TEXT NOT NULL REFERENCES market_catalog(country_code),
  h3_cell_id TEXT NOT NULL,
  h3_resolution INTEGER NOT NULL,
  track TEXT NOT NULL,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  evidence_count INTEGER NOT NULL DEFAULT 0,
  evidence_status TEXT NOT NULL DEFAULT 'observed',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (snapshot_id, country_code, h3_cell_id, h3_resolution, track),
  CONSTRAINT market_opportunity_track_check CHECK (track IN ('woodworking', 'metal_fabrication')),
  CONSTRAINT market_opportunity_resolution_check CHECK (h3_resolution BETWEEN 0 AND 15)
);

CREATE INDEX IF NOT EXISTS idx_market_opportunity_current
  ON market_opportunity_cells(country_code, track, h3_resolution, active, snapshot_id);
CREATE INDEX IF NOT EXISTS idx_market_opportunity_cell
  ON market_opportunity_cells(h3_cell_id, h3_resolution, active);
