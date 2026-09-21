ALTER TABLE ipintel.http_events
  ADD COLUMN IF NOT EXISTS visitor_id Nullable(String);

ALTER TABLE ipintel.http_events
  ADD COLUMN IF NOT EXISTS identity_method LowCardinality(String) DEFAULT 'none';

ALTER TABLE ipintel.http_events
  ADD COLUMN IF NOT EXISTS cf_country LowCardinality(String) DEFAULT '';

ALTER TABLE ipintel.http_events
  ADD COLUMN IF NOT EXISTS cf_asn UInt32 DEFAULT 0;

ALTER TABLE ipintel.http_events
  ADD COLUMN IF NOT EXISTS cf_as_org String DEFAULT '';

ALTER TABLE ipintel.http_events
  ADD COLUMN IF NOT EXISTS cf_bot_score Nullable(UInt8);
