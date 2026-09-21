-- Retention TTL configuration for ClickHouse tables
-- Rationale:
-- http_events: Retained for 210 days (~7 months) to satisfy Country Demand 90d + 90d previous horizon (180 days) plus a 30-day operational buffer.
-- behavior_events: Retained for 120 days (~4 months) to satisfy 90d behavior session aggregation plus a 30-day buffer.

ALTER TABLE ipintel.http_events
  MODIFY TTL event_time + INTERVAL 210 DAY;

ALTER TABLE ipintel.behavior_events
  MODIFY TTL event_time + INTERVAL 120 DAY;
