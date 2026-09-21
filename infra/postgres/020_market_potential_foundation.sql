-- Market Potential v1: product-specific geo units and explainable summaries.
-- This is deliberately separate from the legacy country/track opportunity tables.

CREATE TABLE IF NOT EXISTS geo_unit (
  geo_unit_id TEXT PRIMARY KEY,
  country_code TEXT NOT NULL,
  unit_type TEXT NOT NULL,
  display_name TEXT NOT NULL,
  lat DOUBLE PRECISION,
  lng DOUBLE PRECISION,
  bounding_geometry JSONB NOT NULL DEFAULT '{}'::jsonb,
  population BIGINT,
  industrial_cluster_flag BOOLEAN NOT NULL DEFAULT FALSE,
  notes TEXT,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT geo_unit_type_check CHECK (unit_type IN ('admin_province','admin_city','industrial_cluster')),
  CONSTRAINT geo_unit_lat_check CHECK (lat IS NULL OR lat BETWEEN -90 AND 90),
  CONSTRAINT geo_unit_lng_check CHECK (lng IS NULL OR lng BETWEEN -180 AND 180),
  CONSTRAINT geo_unit_population_check CHECK (population IS NULL OR population >= 0)
);

CREATE INDEX IF NOT EXISTS idx_geo_unit_country_active
  ON geo_unit(country_code, active, unit_type);

CREATE TABLE IF NOT EXISTS product_track (
  product_id TEXT PRIMARY KEY,
  brand_id TEXT NOT NULL,
  category TEXT NOT NULL,
  hs_codes JSONB NOT NULL DEFAULT '[]'::jsonb,
  display_name TEXT,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT product_track_category_check CHECK (category IN ('woodworking','metalworking'))
);

CREATE INDEX IF NOT EXISTS idx_product_track_brand_category
  ON product_track(brand_id, category, active);

CREATE TABLE IF NOT EXISTS data_source_registry (
  source_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  tier SMALLINT NOT NULL,
  access_method TEXT NOT NULL,
  refresh_frequency TEXT NOT NULL,
  geo_resolution TEXT NOT NULL,
  used_for JSONB NOT NULL DEFAULT '[]'::jsonb,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT data_source_tier_check CHECK (tier BETWEEN 1 AND 3),
  CONSTRAINT data_source_access_check CHECK (access_method IN ('api_key_free','api_no_key','bulk_download','manual_pdf','places_search','internal_crm')),
  CONSTRAINT data_source_refresh_check CHECK (refresh_frequency IN ('annual','quarterly','realtime')),
  CONSTRAINT data_source_resolution_check CHECK (geo_resolution IN ('country','geo_unit'))
);

CREATE TABLE IF NOT EXISTS market_city_product_summary (
  snapshot_id TEXT NOT NULL,
  geo_unit_id TEXT NOT NULL REFERENCES geo_unit(geo_unit_id) ON DELETE CASCADE,
  country_code TEXT NOT NULL,
  product_id TEXT NOT NULL REFERENCES product_track(product_id) ON DELETE CASCADE,
  score DOUBLE PRECISION,
  score_type TEXT NOT NULL,
  confidence DOUBLE PRECISION NOT NULL,
  data_coverage SMALLINT NOT NULL DEFAULT 0,
  data_coverage_total SMALLINT NOT NULL DEFAULT 5,
  country_product_prior DOUBLE PRECISION,
  city_fit DOUBLE PRECISION,
  sales_validation_score DOUBLE PRECISION,
  competition_presence INTEGER,
  competition_strength DOUBLE PRECISION,
  market_validation TEXT,
  white_space_score DOUBLE PRECISION,
  rfq_count_12m INTEGER NOT NULL DEFAULT 0,
  win_rate DOUBLE PRECISION,
  top_positive_reasons JSONB NOT NULL DEFAULT '[]'::jsonb,
  top_negative_reasons JSONB NOT NULL DEFAULT '[]'::jsonb,
  limitations JSONB NOT NULL DEFAULT '[]'::jsonb,
  source_updated_at JSONB NOT NULL DEFAULT '{}'::jsonb,
  model_version TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (snapshot_id, geo_unit_id, product_id),
  CONSTRAINT market_summary_score_type_check CHECK (score_type IN ('observed','estimated','prior')),
  CONSTRAINT market_summary_score_check CHECK (score IS NULL OR score BETWEEN 0 AND 100),
  CONSTRAINT market_summary_confidence_check CHECK (confidence BETWEEN 0 AND 1),
  CONSTRAINT market_summary_coverage_check CHECK (data_coverage BETWEEN 0 AND data_coverage_total AND data_coverage_total > 0),
  CONSTRAINT market_summary_prior_check CHECK (country_product_prior IS NULL OR country_product_prior BETWEEN 0 AND 100),
  CONSTRAINT market_summary_city_fit_check CHECK (city_fit IS NULL OR city_fit BETWEEN 0 AND 100),
  CONSTRAINT market_summary_sales_check CHECK (sales_validation_score IS NULL OR sales_validation_score BETWEEN 0 AND 100),
  CONSTRAINT market_summary_win_rate_check CHECK (win_rate IS NULL OR win_rate BETWEEN 0 AND 1),
  CONSTRAINT market_summary_rfq_check CHECK (rfq_count_12m >= 0)
);

CREATE INDEX IF NOT EXISTS idx_market_summary_geo_product
  ON market_city_product_summary(country_code, geo_unit_id, product_id, score DESC NULLS LAST);
