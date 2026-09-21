-- OSM membership identifiers are source-geography keys (for example
-- VN:CITY:1022), while geo_unit uses the confirmed VN-GN-* registry. Keep the
-- source key for evidence and do not invent a crosswalk.
ALTER TABLE industrial_demand_evidence
  DROP CONSTRAINT IF EXISTS industrial_demand_evidence_geo_unit_id_fkey;

COMMENT ON COLUMN industrial_demand_evidence.geo_unit_id IS
  'Source geography identifier. It may be an OSM membership key until a verified geo_unit crosswalk exists.';
