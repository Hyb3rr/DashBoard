-- Align the first implementation with the authoritative contracts in data/001-005.
-- Migration 020 is immutable; this migration is intentionally fail-closed when
-- the provisional summary already contains rows.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE OR REPLACE FUNCTION jsonb_text_array(value JSONB)
RETURNS TEXT[]
LANGUAGE SQL
IMMUTABLE
AS $$
  SELECT COALESCE(array_agg(item), '{}'::TEXT[])
  FROM jsonb_array_elements_text(CASE WHEN jsonb_typeof(value) = 'array' THEN value ELSE '[]'::jsonb END) AS item;
$$;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM market_city_product_summary LIMIT 1) THEN
    RAISE EXCEPTION 'market_city_product_summary contains rows; export and migrate them before applying 021';
  END IF;
END $$;

DROP TABLE IF EXISTS market_city_product_summary;

ALTER TABLE product_track ADD COLUMN IF NOT EXISTS hs_code_note TEXT;
ALTER TABLE product_track ALTER COLUMN display_name SET NOT NULL;
ALTER TABLE product_track ALTER COLUMN hs_codes DROP DEFAULT;
ALTER TABLE product_track ALTER COLUMN hs_codes TYPE TEXT[]
  USING jsonb_text_array(hs_codes);
ALTER TABLE product_track ALTER COLUMN hs_codes SET DEFAULT '{}';
ALTER TABLE product_track DROP CONSTRAINT IF EXISTS product_track_category_check;
ALTER TABLE product_track ADD CONSTRAINT product_track_category_check
  CHECK (category IN ('woodworking','metalworking'));
ALTER TABLE product_track ADD CONSTRAINT hs_code_note_required_if_empty
  CHECK (array_length(hs_codes, 1) > 0 OR hs_code_note IS NOT NULL);

ALTER TABLE data_source_registry ALTER COLUMN used_for DROP DEFAULT;
ALTER TABLE data_source_registry ALTER COLUMN used_for TYPE TEXT[]
  USING jsonb_text_array(used_for);
ALTER TABLE data_source_registry ALTER COLUMN used_for SET DEFAULT '{}';
ALTER TABLE data_source_registry ADD COLUMN IF NOT EXISTS last_synced_at TIMESTAMPTZ;
ALTER TABLE data_source_registry ADD COLUMN IF NOT EXISTS notes TEXT;
ALTER TABLE data_source_registry DROP CONSTRAINT IF EXISTS data_source_access_check;
ALTER TABLE data_source_registry ADD CONSTRAINT data_source_access_check
  CHECK (access_method IN ('api_key_free','api_no_key','bulk_download','manual_pdf','places_search','internal'));

CREATE TABLE IF NOT EXISTS market_city_product_summary (
  snapshot_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  geo_unit_id TEXT NOT NULL REFERENCES geo_unit(geo_unit_id),
  country_code CHAR(2) NOT NULL,
  product_id TEXT NOT NULL REFERENCES product_track(product_id),
  score NUMERIC(5,2) CHECK (score BETWEEN 0 AND 100),
  score_type TEXT CHECK (score_type IN ('observed','estimated','prior')),
  confidence NUMERIC(5,2) CHECK (confidence BETWEEN 0 AND 100),
  data_coverage NUMERIC(3,2) CHECK (data_coverage BETWEEN 0 AND 1),
  country_product_prior NUMERIC(5,2),
  city_fit NUMERIC(5,2),
  sales_validation_score NUMERIC(5,2),
  w_internal NUMERIC(4,3),
  w_city NUMERIC(4,3),
  w_country NUMERIC(4,3),
  competition_presence INTEGER,
  competition_strength NUMERIC(5,2),
  market_validation TEXT CHECK (market_validation IN ('validated_market','possibly_saturated','white_space','insufficient_evidence')),
  white_space_score NUMERIC(5,2),
  rfq_count_12m INTEGER,
  win_rate NUMERIC(4,3),
  top_positive_reasons TEXT[],
  top_negative_reasons TEXT[],
  limitations TEXT[],
  calculated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (geo_unit_id, product_id, calculated_at)
);

CREATE INDEX idx_summary_geo_product ON market_city_product_summary(geo_unit_id, product_id);
CREATE INDEX idx_summary_calculated_at ON market_city_product_summary(calculated_at);
