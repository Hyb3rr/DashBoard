-- Bootstrap product/source contracts and the country-product prior read model.
-- Values are derived data snapshots; no country score is calculated here.

CREATE TABLE IF NOT EXISTS market_country_product_prior (
  snapshot_id UUID NOT NULL DEFAULT gen_random_uuid(),
  country_code CHAR(2) NOT NULL,
  product_id TEXT NOT NULL REFERENCES product_track(product_id),
  country_product_prior NUMERIC(5,2),
  data_coverage NUMERIC(3,2) NOT NULL DEFAULT 0 CHECK (data_coverage BETWEEN 0 AND 1),
  source_quality NUMERIC(3,2) CHECK (source_quality IS NULL OR source_quality BETWEEN 0 AND 1),
  signal_values JSONB NOT NULL DEFAULT '{}'::jsonb,
  limitations TEXT[] NOT NULL DEFAULT '{}',
  source_updated_at JSONB NOT NULL DEFAULT '{}'::jsonb,
  model_version TEXT NOT NULL,
  calculated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (snapshot_id, country_code, product_id),
  CHECK (country_product_prior IS NULL OR country_product_prior BETWEEN 0 AND 100)
);

CREATE INDEX IF NOT EXISTS idx_country_product_prior_lookup
  ON market_country_product_prior(country_code, product_id, calculated_at DESC);

INSERT INTO product_track (product_id, brand_id, category, display_name, hs_codes, hs_code_note)
VALUES
 ('cnc_router','shared','woodworking','CNC Router / Machining Centre',ARRAY['846520'],NULL),
 ('panel_saw','shared','woodworking','Panel Saw',ARRAY['846591'],NULL),
 ('planer_moulder','shared','woodworking','Planer / Moulder',ARRAY['846592'],NULL),
 ('sanding_machine','shared','woodworking','Sanding Machine',ARRAY['846593'],NULL),
 ('drilling_mortising','shared','woodworking','Drilling / Mortising Machine',ARRAY['846595'],NULL),
 ('edge_bander','shared','woodworking','Edge Bander',ARRAY[]::TEXT[],'No dedicated HS6; grouped under 846599.'),
 ('furniture_export_proxy','shared','woodworking','Furniture Export Proxy',ARRAY['940330','940340','940350','940360'],'Industry proxy only; not machinery demand.'),
 ('laser_plasma_cutting','himac','metalworking','Laser / Plasma Cutting',ARRAY['8456'],NULL),
 ('machining_centre_metal','himac','metalworking','Machining Centre (metal)',ARRAY['8457'],NULL),
 ('lathe','himac','metalworking','Lathe',ARRAY['8458'],NULL),
 ('drilling_milling_metal','himac','metalworking','Drilling / Milling (metal)',ARRAY['8459'],NULL),
 ('grinding_honing','himac','metalworking','Grinding / Honing',ARRAY['8460'],NULL),
 ('planing_gear_cutting','himac','metalworking','Planing / Gear Cutting',ARRAY['8461'],NULL),
 ('press_brake_forming','himac','metalworking','Press Brake / Forming',ARRAY['8462'],NULL),
 ('other_metal_forming','himac','metalworking','Other Metal Forming',ARRAY['8463'],NULL)
ON CONFLICT (product_id) DO UPDATE SET
  brand_id=EXCLUDED.brand_id, category=EXCLUDED.category, display_name=EXCLUDED.display_name,
  hs_codes=EXCLUDED.hs_codes, hs_code_note=EXCLUDED.hs_code_note, updated_at=now();

INSERT INTO data_source_registry (source_id,name,tier,access_method,refresh_frequency,geo_resolution,used_for,notes)
VALUES
 ('un_comtrade','UN Comtrade API',1,'api_key_free','annual','country',ARRAY['machinery_import_signal','furniture_export'],'Requires registered API key.'),
 ('oec','OEC API',1,'api_key_free','annual','country',ARRAY['machinery_import_signal_backup'],'Backup/validation source.'),
 ('faostat_forestry','FAOSTAT Forestry',1,'bulk_download','annual','country',ARRAY['wood_panel_consumption'],'Bulk download.'),
 ('world_bank_api','World Bank Indicators API',1,'api_no_key','annual','country',ARRAY['manufacturing_value_added','gfcf_construction_proxy'],'No key required.'),
 ('ilostat','ILOSTAT',1,'bulk_download','annual','country',ARRAY['labor_cost_pressure'],'Open bulk data.'),
 ('usgs_cement','USGS Cement Mineral Yearbook',2,'manual_pdf','annual','country',ARRAY['construction_proxy'],'Manual PDF extraction.'),
 ('itc_trademap','ITC Trade Map',2,'api_key_free','annual','country',ARRAY['trade_backup'],'Coverage/paywall varies by user country.'),
 ('google_places','Google Places API',3,'places_search','quarterly','geo_unit',ARRAY['city_business_density','competition_presence'],'Rate limited/paid after quota.'),
 ('osm_overpass','OSM Overpass API',3,'places_search','quarterly','geo_unit',ARRAY['city_business_density_backup'],'Coverage varies by region.'),
 ('internal_crm','Internal CRM/RFQ',1,'internal','realtime','geo_unit',ARRAY['sales_validation','competition_strength'],'Ground-truth sales source.')
ON CONFLICT (source_id) DO UPDATE SET
  name=EXCLUDED.name,tier=EXCLUDED.tier,access_method=EXCLUDED.access_method,
  refresh_frequency=EXCLUDED.refresh_frequency,geo_resolution=EXCLUDED.geo_resolution,
  used_for=EXCLUDED.used_for,notes=EXCLUDED.notes,updated_at=now();
