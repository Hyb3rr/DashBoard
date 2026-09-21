CREATE TABLE IF NOT EXISTS city_overall_opportunity_snapshot (
  snapshot_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  country_code TEXT NOT NULL,
  peer_group TEXT NOT NULL,
  model_version TEXT NOT NULL,
  calculated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  status TEXT NOT NULL DEFAULT 'staging',
  published_at TIMESTAMPTZ,
  CONSTRAINT city_overall_snapshot_status_check CHECK (status IN ('staging','published','superseded','failed'))
);

CREATE TABLE IF NOT EXISTS city_overall_opportunity (
  snapshot_id UUID NOT NULL REFERENCES city_overall_opportunity_snapshot(snapshot_id) ON DELETE CASCADE,
  country_code TEXT NOT NULL,
  geo_unit_id TEXT NOT NULL,
  score DOUBLE PRECISION,
  evidence_coverage DOUBLE PRECISION NOT NULL DEFAULT 0,
  components JSONB NOT NULL DEFAULT '{}'::jsonb,
  limitations JSONB NOT NULL DEFAULT '[]'::jsonb,
  calculated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (snapshot_id, geo_unit_id),
  CONSTRAINT city_overall_score_check CHECK (score IS NULL OR score BETWEEN 0 AND 100),
  CONSTRAINT city_overall_coverage_check CHECK (evidence_coverage BETWEEN 0 AND 100)
);

CREATE INDEX IF NOT EXISTS idx_city_overall_published ON city_overall_opportunity_snapshot(country_code, status, published_at DESC);
CREATE INDEX IF NOT EXISTS idx_city_overall_rows ON city_overall_opportunity(country_code, geo_unit_id, snapshot_id);
