-- Immutable evidence rows and an explicitly published snapshot marker.
-- A snapshot is visible to readers only after its producer marks it published.
CREATE TABLE IF NOT EXISTS industrial_demand_snapshot (
  snapshot_id UUID PRIMARY KEY,
  country_code CHAR(2) NOT NULL,
  geo_scope TEXT NOT NULL DEFAULT 'confirmed_administrative_geo_unit',
  model_version TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  product_count INTEGER NOT NULL DEFAULT 0 CHECK (product_count >= 0),
  evidence_count INTEGER NOT NULL DEFAULT 0 CHECK (evidence_count >= 0),
  error_message TEXT,
  started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at TIMESTAMPTZ,
  CONSTRAINT industrial_demand_snapshot_scope_check
    CHECK (geo_scope = 'confirmed_administrative_geo_unit'),
  CONSTRAINT industrial_demand_snapshot_status_check
    CHECK (status IN ('pending', 'published', 'failed')),
  CONSTRAINT industrial_demand_snapshot_published_check
    CHECK (status <> 'published' OR completed_at IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS idx_industrial_demand_snapshot_latest
  ON industrial_demand_snapshot(country_code, status, completed_at DESC);

CREATE TABLE IF NOT EXISTS industrial_demand_evidence (
  snapshot_id UUID NOT NULL REFERENCES industrial_demand_snapshot(snapshot_id) ON DELETE CASCADE,
  evidence_id TEXT NOT NULL,
  country_code CHAR(2) NOT NULL,
  geo_unit_id TEXT REFERENCES geo_unit(geo_unit_id) ON DELETE RESTRICT,
  product_id TEXT REFERENCES product_track(product_id) ON DELETE RESTRICT,
  source_id TEXT NOT NULL REFERENCES data_source_registry(source_id) ON DELETE RESTRICT,
  source_geo_scope TEXT NOT NULL,
  observed_value JSONB,
  unit TEXT,
  observed_period TEXT NOT NULL,
  collected_at TIMESTAMPTZ NOT NULL,
  mapping_version TEXT NOT NULL,
  limitations JSONB NOT NULL DEFAULT '[]'::jsonb,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  PRIMARY KEY (snapshot_id, evidence_id),
  CONSTRAINT industrial_demand_evidence_scope_check
    CHECK (source_geo_scope IN ('country', 'geo_unit')),
  CONSTRAINT industrial_demand_evidence_geo_check
    CHECK ((source_geo_scope = 'country' AND geo_unit_id IS NULL)
        OR (source_geo_scope = 'geo_unit' AND geo_unit_id IS NOT NULL)),
  CONSTRAINT industrial_demand_evidence_subject_check
    CHECK (product_id IS NOT NULL OR metadata ? 'industry_proxy')
);

CREATE INDEX IF NOT EXISTS idx_industrial_demand_evidence_latest
  ON industrial_demand_evidence(country_code, geo_unit_id, product_id, collected_at DESC);

