CREATE TABLE IF NOT EXISTS ipintel.behavior_events (
  event_time DateTime64(3, 'UTC'),
  ingested_at DateTime64(3, 'UTC'),
  event_id String,
  visitor_id String,
  session_id String,
  event_name LowCardinality(String),
  path String,
  engagement_ms Nullable(Float64),
  key_event_name Nullable(String),
  payload_hash FixedString(64)
)
ENGINE = ReplacingMergeTree(ingested_at)
PARTITION BY toYYYYMM(event_time)
ORDER BY (event_id, event_time, visitor_id, session_id);
