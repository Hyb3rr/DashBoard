-- A snapshot contains one row per geo unit and product; snapshot_id alone is
-- intentionally not unique across the rows in the same snapshot.
ALTER TABLE market_city_product_summary
  DROP CONSTRAINT IF EXISTS market_city_product_summary_pkey;

ALTER TABLE market_city_product_summary
  ADD CONSTRAINT market_city_product_summary_pkey
  PRIMARY KEY (snapshot_id, geo_unit_id, product_id);

CREATE INDEX IF NOT EXISTS idx_market_summary_latest
  ON market_city_product_summary(geo_unit_id, product_id, calculated_at DESC);
