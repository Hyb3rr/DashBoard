CREATE TABLE IF NOT EXISTS privacy_network_change_history (
  id BIGSERIAL PRIMARY KEY,
  changed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  source TEXT NOT NULL,
  kind TEXT NOT NULL,
  network CIDR NOT NULL,
  change_type TEXT NOT NULL CHECK (change_type IN ('added', 'changed', 'removed', 'reactivated')),
  old_state JSONB,
  new_state JSONB,
  refresh_id TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_privacy_network_change_history_lookup
  ON privacy_network_change_history (source, kind, changed_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_privacy_network_change_history_retention
  ON privacy_network_change_history (changed_at, id);
