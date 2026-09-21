ALTER TABLE ipintel.behavior_events
  MODIFY COLUMN cf_js_detection_passed Nullable(UInt8);

ALTER TABLE ipintel.behavior_events
  MODIFY COLUMN geo_conflict Nullable(UInt8);

ALTER TABLE ipintel.behavior_events
  MODIFY COLUMN is_hosting Nullable(UInt8);

ALTER TABLE ipintel.behavior_events
  MODIFY COLUMN is_mobile Nullable(UInt8);

ALTER TABLE ipintel.behavior_events
  MODIFY COLUMN is_proxy Nullable(UInt8);

ALTER TABLE ipintel.behavior_events
  MODIFY COLUMN is_scanner Nullable(UInt8);

ALTER TABLE ipintel.behavior_events
  MODIFY COLUMN is_tor Nullable(UInt8);

ALTER TABLE ipintel.behavior_events
  MODIFY COLUMN is_vpn Nullable(UInt8);
