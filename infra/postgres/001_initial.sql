CREATE TABLE IF NOT EXISTS dataset_runs (
  id TEXT PRIMARY KEY,
  dataset_type TEXT NOT NULL CHECK (dataset_type IN ('live', 'file')),
  filename TEXT,
  active BOOLEAN NOT NULL DEFAULT FALSE,
  start_time TIMESTAMPTZ,
  end_time TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ip_minute_features (
  dataset_id TEXT NOT NULL,
  ip INET NOT NULL,
  bucket_minute TIMESTAMPTZ NOT NULL,
  requests BIGINT NOT NULL DEFAULT 0,
  status_2xx BIGINT NOT NULL DEFAULT 0,
  status_3xx BIGINT NOT NULL DEFAULT 0,
  status_4xx BIGINT NOT NULL DEFAULT 0,
  status_5xx BIGINT NOT NULL DEFAULT 0,
  status_403 BIGINT NOT NULL DEFAULT 0,
  status_404 BIGINT NOT NULL DEFAULT 0,
  post_requests BIGINT NOT NULL DEFAULT 0,
  sensitive_hits BIGINT NOT NULL DEFAULT 0,
  wp_login_hits BIGINT NOT NULL DEFAULT 0,
  bot_hits BIGINT NOT NULL DEFAULT 0,
  bytes_sum BIGINT NOT NULL DEFAULT 0,
  first_seen TIMESTAMPTZ,
  last_seen TIMESTAMPTZ,
  PRIMARY KEY (dataset_id, ip, bucket_minute)
);

CREATE TABLE IF NOT EXISTS processed_batches (
  batch_id TEXT PRIMARY KEY,
  dataset_id TEXT NOT NULL,
  source_id TEXT,
  start_offset BIGINT,
  end_offset BIGINT,
  event_count INTEGER NOT NULL DEFAULT 0,
  processed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS log_sources (
  source_id TEXT PRIMARY KEY,
  log_key TEXT NOT NULL,
  last_offset BIGINT NOT NULL DEFAULT 0,
  status TEXT,
  last_error TEXT,
  last_event_at TIMESTAMPTZ,
  lease_owner TEXT,
  lease_expires_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_processed_batches_source_offset
  ON processed_batches(source_id, end_offset);

CREATE INDEX IF NOT EXISTS idx_ip_minute_features_window
  ON ip_minute_features(dataset_id, bucket_minute, ip);

CREATE INDEX IF NOT EXISTS idx_ip_minute_features_ip_window
  ON ip_minute_features(dataset_id, ip, bucket_minute);

CREATE TABLE IF NOT EXISTS ip_minute_path_seen (
  dataset_id TEXT NOT NULL,
  ip INET NOT NULL,
  bucket_minute TIMESTAMPTZ NOT NULL,
  path TEXT NOT NULL,
  requests BIGINT NOT NULL DEFAULT 0,
  status_4xx BIGINT NOT NULL DEFAULT 0,
  status_5xx BIGINT NOT NULL DEFAULT 0,
  PRIMARY KEY (dataset_id, ip, bucket_minute, path)
);

CREATE INDEX IF NOT EXISTS idx_ip_minute_path_seen_ip_window
  ON ip_minute_path_seen(dataset_id, ip, bucket_minute);

CREATE TABLE IF NOT EXISTS ip_profiles (
  ip INET PRIMARY KEY,
  country TEXT,
  country_code TEXT,
  city TEXT,
  region TEXT,
  asn TEXT,
  organization TEXT,
  isp TEXT,
  network_type TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE ip_profiles
  ADD COLUMN IF NOT EXISTS latitude DOUBLE PRECISION,
  ADD COLUMN IF NOT EXISTS longitude DOUBLE PRECISION,
  ADD COLUMN IF NOT EXISTS timezone TEXT,
  ADD COLUMN IF NOT EXISTS ip_prefix CIDR,
  ADD COLUMN IF NOT EXISTS organization_confidence INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS identity_evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS is_hosting BOOLEAN,
  ADD COLUMN IF NOT EXISTS is_vpn BOOLEAN,
  ADD COLUMN IF NOT EXISTS is_proxy BOOLEAN,
  ADD COLUMN IF NOT EXISTS is_tor BOOLEAN,
  ADD COLUMN IF NOT EXISTS proxy_type TEXT,
  ADD COLUMN IF NOT EXISTS abuse_score INTEGER,
  ADD COLUMN IF NOT EXISTS abuse_reports INTEGER,
  ADD COLUMN IF NOT EXISTS reputation JSONB NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS enrichment_status TEXT NOT NULL DEFAULT 'partial',
  ADD COLUMN IF NOT EXISTS core_enrichment_status TEXT NOT NULL DEFAULT 'partial',
  ADD COLUMN IF NOT EXISTS privacy_enrichment_status TEXT NOT NULL DEFAULT 'unknown',
  ADD COLUMN IF NOT EXISTS threat_enrichment_status TEXT NOT NULL DEFAULT 'unknown',
  ADD COLUMN IF NOT EXISTS provider_errors JSONB NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS provider_status JSONB NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN IF NOT EXISTS field_sources JSONB NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN IF NOT EXISTS next_retry_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS enrichment_attempts INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS privacy_recheck_due_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS risk_score INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS risk_level TEXT NOT NULL DEFAULT 'unknown',
  ADD COLUMN IF NOT EXISTS evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS sources JSONB NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS network_location JSONB NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN IF NOT EXISTS location_confidence INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS location_disputed BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS location_scope TEXT,
  ADD COLUMN IF NOT EXISTS network_type_source TEXT,
  ADD COLUMN IF NOT EXISTS asn_source TEXT,
  ADD COLUMN IF NOT EXISTS geo_sources JSONB NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS geo_resolved_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS geo_expires_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS fetched_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

CREATE TABLE IF NOT EXISTS ip_observations_state (
  ip INET PRIMARY KEY,
  payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  ruleset_hash TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS rule_firing_state (
  ip INET NOT NULL,
  rule_id TEXT NOT NULL,
  "window" TEXT NOT NULL,
  ruleset_hash TEXT NOT NULL,
  first_fired_at TIMESTAMPTZ NOT NULL,
  last_fired_at TIMESTAMPTZ NOT NULL,
  last_seen_seq BIGINT NOT NULL DEFAULT 0,
  PRIMARY KEY (ip, rule_id, "window")
);

CREATE TABLE IF NOT EXISTS alert_outbox (
  id BIGSERIAL PRIMARY KEY,
  ip INET NOT NULL,
  event_type TEXT NOT NULL,
  payload JSONB NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  attempts INTEGER NOT NULL DEFAULT 0,
  next_retry_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  delivered_at TIMESTAMPTZ,
  lease_owner TEXT,
  lease_until TIMESTAMPTZ,
  idempotency_key TEXT UNIQUE,
  last_error TEXT
);

CREATE TABLE IF NOT EXISTS ip_dispositions (
  ip INET PRIMARY KEY,
  state TEXT NOT NULL DEFAULT 'new',
  suggested_state TEXT,
  assigned_to TEXT,
  note TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  history JSONB NOT NULL DEFAULT '[]'::jsonb
);

CREATE TABLE IF NOT EXISTS change_consumer_state (
  consumer_id TEXT PRIMARY KEY,
  last_seq BIGINT NOT NULL DEFAULT 0,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  status TEXT NOT NULL DEFAULT 'active'
);

CREATE TABLE IF NOT EXISTS intel_source_status (
  source_name TEXT PRIMARY KEY,
  last_run_at TIMESTAMPTZ,
  last_status TEXT,
  last_error TEXT,
  records_upserted BIGINT NOT NULL DEFAULT 0,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS geo_prefixes (
  network CIDR NOT NULL,
  asn TEXT,
  organization TEXT,
  network_type TEXT,
  rir TEXT,
  registration_country TEXT,
  source TEXT NOT NULL,
  source_version TEXT,
  first_seen TIMESTAMPTZ,
  last_seen TIMESTAMPTZ,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  PRIMARY KEY (network, source)
);
CREATE INDEX IF NOT EXISTS idx_pg_geo_prefixes_network ON geo_prefixes USING gist(network inet_ops);

CREATE TABLE IF NOT EXISTS geo_location_observations (
  network CIDR NOT NULL,
  source TEXT NOT NULL,
  country TEXT,
  country_code TEXT,
  source_confidence INTEGER NOT NULL DEFAULT 0,
  location_scope TEXT,
  latitude DOUBLE PRECISION,
  longitude DOUBLE PRECISION,
  city TEXT,
  observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (network, source)
);

CREATE TABLE IF NOT EXISTS privacy_network_history (
  network CIDR NOT NULL,
  kind TEXT NOT NULL,
  provider TEXT,
  proxy_type TEXT,
  score DOUBLE PRECISION,
  source TEXT NOT NULL,
  first_seen TIMESTAMPTZ,
  last_seen TIMESTAMPTZ,
  observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS geo_source_status (
  source_name TEXT PRIMARY KEY,
  last_run_at TIMESTAMPTZ,
  last_status TEXT,
  last_error TEXT,
  records_upserted BIGINT NOT NULL DEFAULT 0,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS geo_resolutions (
  ip INET PRIMARY KEY,
  network CIDR,
  asn TEXT,
  organization TEXT,
  network_type TEXT,
  country TEXT,
  country_code TEXT,
  latitude DOUBLE PRECISION,
  longitude DOUBLE PRECISION,
  city TEXT,
  city_source TEXT,
  city_disputed BOOLEAN NOT NULL DEFAULT FALSE,
  city_confidence INTEGER,
  city_distance_km DOUBLE PRECISION,
  confidence INTEGER NOT NULL DEFAULT 0,
  disputed BOOLEAN NOT NULL DEFAULT FALSE,
  location_scope TEXT,
  source_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
  evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
  ruleset_version TEXT,
  resolved_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS geo_change_history (
  id BIGSERIAL PRIMARY KEY,
  network CIDR,
  ip INET,
  old_country_code TEXT,
  new_country_code TEXT,
  detected_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE geo_resolutions ADD COLUMN IF NOT EXISTS city_source TEXT;
ALTER TABLE geo_resolutions ADD COLUMN IF NOT EXISTS city_disputed BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE geo_resolutions ADD COLUMN IF NOT EXISTS city_confidence INTEGER;
ALTER TABLE geo_resolutions ADD COLUMN IF NOT EXISTS city_distance_km DOUBLE PRECISION;

CREATE TABLE IF NOT EXISTS geo_source_status (
  source_name TEXT PRIMARY KEY,
  last_run_at TIMESTAMPTZ,
  last_status TEXT,
  last_error TEXT,
  records_upserted BIGINT NOT NULL DEFAULT 0,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS privacy_networks (
  network CIDR NOT NULL,
  kind TEXT NOT NULL,
  provider TEXT,
  proxy_type TEXT,
  score DOUBLE PRECISION,
  source TEXT NOT NULL,
  first_seen TIMESTAMPTZ,
  last_seen TIMESTAMPTZ,
  checked_at TIMESTAMPTZ,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  PRIMARY KEY (source, kind, network)
);

CREATE TABLE IF NOT EXISTS threat_indicators (
  network CIDR NOT NULL,
  source TEXT NOT NULL,
  category TEXT NOT NULL,
  confidence DOUBLE PRECISION,
  first_seen TIMESTAMPTZ,
  last_seen TIMESTAMPTZ,
  checked_at TIMESTAMPTZ,
  evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  PRIMARY KEY (network, source, category)
);

CREATE TABLE IF NOT EXISTS ip_observations (
  ip INET PRIMARY KEY,
  payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ip_classification_state (
  ip INET PRIMARY KEY,
  label TEXT NOT NULL,
  score INTEGER NOT NULL DEFAULT 0,
  confidence INTEGER,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_alert_at TIMESTAMPTZ,
  last_alert_label TEXT
);

CREATE TABLE IF NOT EXISTS ip_change_log (
  seq BIGSERIAL PRIMARY KEY,
  dataset_id TEXT NOT NULL DEFAULT 'live',
  ip INET NOT NULL,
  reason TEXT NOT NULL,
  changed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  old_label TEXT,
  new_label TEXT,
  old_score INTEGER,
  new_score INTEGER
);

CREATE TABLE IF NOT EXISTS region_profiles (
  country_code TEXT PRIMARY KEY,
  country_name TEXT NOT NULL,
  economic_indicators JSONB NOT NULL DEFAULT '{}'::jsonb,
  cultural_context JSONB NOT NULL DEFAULT '[]'::jsonb,
  conflict_indicators JSONB NOT NULL DEFAULT '[]'::jsonb,
  sources JSONB NOT NULL DEFAULT '[]'::jsonb,
  observed_ip_count INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL DEFAULT ''
);
