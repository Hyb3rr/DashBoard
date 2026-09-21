ALTER TABLE ipintel.behavior_events
  ADD COLUMN IF NOT EXISTS assigned_country Nullable(String);

ALTER TABLE ipintel.behavior_events
  ADD COLUMN IF NOT EXISTS country_source Nullable(String);

ALTER TABLE ipintel.behavior_events
  ADD COLUMN IF NOT EXISTS geo_confidence Nullable(Float64);

ALTER TABLE ipintel.behavior_events
  ADD COLUMN IF NOT EXISTS geo_conflict Nullable(UInt8);

ALTER TABLE ipintel.behavior_events
  ADD COLUMN IF NOT EXISTS cf_bot_score Nullable(UInt8);

ALTER TABLE ipintel.behavior_events
  ADD COLUMN IF NOT EXISTS cf_js_detection_passed Nullable(UInt8);

ALTER TABLE ipintel.behavior_events
  ADD COLUMN IF NOT EXISTS is_tor Nullable(UInt8);

ALTER TABLE ipintel.behavior_events
  ADD COLUMN IF NOT EXISTS is_vpn Nullable(UInt8);

ALTER TABLE ipintel.behavior_events
  ADD COLUMN IF NOT EXISTS is_proxy Nullable(UInt8);

ALTER TABLE ipintel.behavior_events
  ADD COLUMN IF NOT EXISTS is_hosting Nullable(UInt8);

ALTER TABLE ipintel.behavior_events
  ADD COLUMN IF NOT EXISTS is_mobile Nullable(UInt8);

ALTER TABLE ipintel.behavior_events
  ADD COLUMN IF NOT EXISTS is_scanner Nullable(UInt8);
