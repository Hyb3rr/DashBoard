-- Phase 5A: auxiliary local evidence substrate. No scoring or ranking.
CREATE TABLE IF NOT EXISTS market_cell_auxiliary_evidence (
  snapshot_id TEXT NOT NULL REFERENCES market_osm_snapshots(snapshot_id) ON DELETE CASCADE,
  country_code TEXT NOT NULL REFERENCES market_catalog(country_code),
  h3_cell_id TEXT NOT NULL,
  h3_resolution INTEGER NOT NULL,
  track TEXT NOT NULL,
  source TEXT NOT NULL,
  source_version TEXT NOT NULL,
  source_hash TEXT NOT NULL,
  industrial_land_count INTEGER NOT NULL DEFAULT 0,
  motorway_count INTEGER NOT NULL DEFAULT 0,
  primary_road_count INTEGER NOT NULL DEFAULT 0,
  railway_count INTEGER NOT NULL DEFAULT 0,
  port_count INTEGER NOT NULL DEFAULT 0,
  airport_count INTEGER NOT NULL DEFAULT 0,
  access_observation_count INTEGER NOT NULL DEFAULT 0,
  evidence_status TEXT NOT NULL DEFAULT 'observed',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (snapshot_id, country_code, h3_cell_id, h3_resolution, track),
  CONSTRAINT market_aux_track_check CHECK (track IN ('woodworking', 'metal_fabrication')),
  CONSTRAINT market_aux_resolution_check CHECK (h3_resolution BETWEEN 0 AND 15),
  CONSTRAINT market_aux_status_check CHECK (evidence_status IN ('observed', 'unavailable', 'stale'))
);

CREATE INDEX IF NOT EXISTS idx_market_aux_current_query
  ON market_cell_auxiliary_evidence(country_code, track, h3_resolution, snapshot_id);
CREATE INDEX IF NOT EXISTS idx_market_aux_cell
  ON market_cell_auxiliary_evidence(h3_cell_id, h3_resolution);
