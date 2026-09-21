-- Public city candidates are reference data only until sales confirms them.
ALTER TABLE geo_unit
  ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'confirmed';

ALTER TABLE geo_unit
  DROP CONSTRAINT IF EXISTS geo_unit_status_check;

ALTER TABLE geo_unit
  ADD CONSTRAINT geo_unit_status_check
  CHECK (status IN ('public_candidate', 'confirmed', 'retired'));

CREATE INDEX IF NOT EXISTS idx_geo_unit_status_active
  ON geo_unit(status, active, country_code);
