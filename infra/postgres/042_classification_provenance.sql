ALTER TABLE ip_classification_state
  ADD COLUMN IF NOT EXISTS input_contract_version TEXT,
  ADD COLUMN IF NOT EXISTS input_fingerprint TEXT;
