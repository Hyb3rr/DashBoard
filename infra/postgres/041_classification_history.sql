CREATE TABLE IF NOT EXISTS ip_classification_history (
  id BIGSERIAL PRIMARY KEY,
  event_key TEXT NOT NULL UNIQUE,
  dataset_id TEXT NOT NULL,
  ip INET NOT NULL,
  source TEXT NOT NULL CHECK (source IN ('traffic', 'enrichment', 'alert_snapshot', 'change_log')),
  changed_at TIMESTAMPTZ NOT NULL,
  previous_classification JSONB NOT NULL DEFAULT '{}'::jsonb,
  current_classification JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_ip_classification_history_ip_time
  ON ip_classification_history (ip, changed_at DESC, id DESC);

-- Preserve prior escalation snapshots already retained by the alert inbox.
INSERT INTO ip_classification_history (
  event_key, dataset_id, ip, source, changed_at,
  previous_classification, current_classification
)
SELECT
  'alert:' || id::text,
  'live',
  ip,
  'alert_snapshot',
  created_at,
  previous_classification,
  current_classification
FROM alerts
WHERE reason_type IN ('classification_transition', 'critical_recurrence')
ON CONFLICT (event_key) DO NOTHING;

-- Backfill retained downward transitions; old change-feed rows have no evidence snapshot.
INSERT INTO ip_classification_history (
  event_key, dataset_id, ip, source, changed_at,
  previous_classification, current_classification
)
SELECT
  'change_log:' || seq::text,
  dataset_id,
  ip,
  'change_log',
  changed_at,
  jsonb_build_object('label', old_label, 'score', old_score),
  jsonb_build_object('label', new_label, 'score', new_score, 'evidence', '[]'::jsonb)
FROM ip_change_log
WHERE reason IN ('classification', 'enrichment_classification')
  AND old_label IS NOT NULL
  AND new_label IS NOT NULL
  AND CASE old_label
        WHEN 'critical' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0
      END > CASE new_label
        WHEN 'critical' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0
      END
ON CONFLICT (event_key) DO NOTHING;
