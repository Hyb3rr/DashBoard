-- Replace migration-time timestamps for historical inventory alerts with the
-- latest reliable stored observation that led to the current classification.
WITH source_times AS (
  SELECT
    cs.ip,
    cs.label,
    MAX(cl.changed_at) FILTER (
      WHERE cl.reason = 'classification' AND cl.new_label = cs.label
    ) AS classification_at,
    MAX(cl.changed_at) FILTER (WHERE cl.reason = 'traffic') AS traffic_at,
    NULLIF(o.payload->>'last_seen', '')::timestamptz AS last_seen_at
  FROM ip_classification_state cs
  LEFT JOIN ip_change_log cl ON cl.ip = cs.ip
  LEFT JOIN ip_observations_state o ON o.ip = cs.ip
  WHERE cs.label IN ('low', 'medium', 'critical')
  GROUP BY cs.ip, cs.label, o.payload
)
UPDATE alerts a
SET created_at = LEAST(
  COALESCE(s.classification_at, s.traffic_at, s.last_seen_at, a.created_at),
  a.created_at
),
updated_at = a.updated_at
FROM source_times s
WHERE a.reason_type = 'initial_inventory'
  AND a.ip = s.ip
  AND a.severity = s.label;
