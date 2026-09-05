-- Make the current deterministic severity inventory visible to the Alerts page once.
-- This is deliberately separate from transition alerts and is idempotent.
INSERT INTO alerts (
  ip, severity, reason_type, title, description, evidence,
  evidence_fingerprint, previous_classification, current_classification,
  status, dedupe_key
)
SELECT
  cs.ip,
  cs.label,
  'initial_inventory',
  INITCAP(cs.label) || ' current classification for ' || host(cs.ip),
  'Current deterministic classification loaded into the alert inbox.',
  COALESCE(p.evidence, '[]'::jsonb) || COALESCE(o.payload->'behavior_evidence', '[]'::jsonb),
  md5((COALESCE(p.evidence, '[]'::jsonb) || COALESCE(o.payload->'behavior_evidence', '[]'::jsonb))::text),
  '{}'::jsonb,
  jsonb_build_object('label', cs.label, 'score', cs.score, 'confidence', cs.confidence),
  'new',
  'initial_inventory:' || host(cs.ip) || ':' || cs.label
FROM ip_classification_state cs
LEFT JOIN ip_profiles p ON p.ip = cs.ip
LEFT JOIN ip_observations_state o ON o.ip = cs.ip
WHERE cs.label IN ('low', 'medium', 'critical')
ON CONFLICT (dedupe_key) DO NOTHING;
