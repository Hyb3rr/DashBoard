-- Inventory alerts represent the last recorded classification event, not migration time.
-- Transition and recurrence alerts keep their immutable creation timestamp.
UPDATE alerts a
SET created_at = cs.updated_at,
    updated_at = GREATEST(a.updated_at, cs.updated_at)
FROM ip_classification_state cs
WHERE a.reason_type = 'initial_inventory'
  AND a.ip = cs.ip
  AND cs.updated_at IS NOT NULL
  AND a.created_at <> cs.updated_at;
