-- Alerts and classifications are current operational read models, not audit history.
-- Remove rows whose IP no longer has an authoritative current identity.
DELETE FROM alerts a
WHERE NOT EXISTS (SELECT 1 FROM ip_profiles p WHERE p.ip = a.ip)
  AND NOT EXISTS (SELECT 1 FROM ip_observations_state o WHERE o.ip = a.ip);

DELETE FROM ip_classification_state cs
WHERE NOT EXISTS (SELECT 1 FROM ip_profiles p WHERE p.ip = cs.ip)
  AND NOT EXISTS (SELECT 1 FROM ip_observations_state o WHERE o.ip = cs.ip);
