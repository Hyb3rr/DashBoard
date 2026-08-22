CREATE DATABASE IF NOT EXISTS ipintel;

CREATE TABLE IF NOT EXISTS ipintel.http_events (
  event_time DateTime64(3, 'UTC'),
  ingested_at DateTime64(3, 'UTC'),
  dataset_id LowCardinality(String),
  source_id LowCardinality(String),
  source_offset UInt64,
  event_id FixedString(64),
  src_ip IPv6,
  method LowCardinality(String),
  path String,
  status UInt16,
  bytes_sent UInt64,
  referer String,
  user_agent String,
  raw_line String
)
ENGINE = ReplacingMergeTree(ingested_at)
PARTITION BY toYYYYMM(event_time)
ORDER BY (dataset_id, event_id, event_time, src_ip, source_id, source_offset)
SETTINGS index_granularity = 8192;
