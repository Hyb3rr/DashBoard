CREATE TABLE IF NOT EXISTS page_classification_rules (
    id BIGSERIAL PRIMARY KEY,
    pattern TEXT NOT NULL,
    page_type TEXT NOT NULL CHECK (page_type IN ('product','content','other')),
    priority INTEGER NOT NULL DEFAULT 0,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS page_classification_rules_active_priority_idx
    ON page_classification_rules (active, priority DESC, id);

CREATE TABLE IF NOT EXISTS country_demand_identity_config (
    config_key TEXT PRIMARY KEY,
    visitor_identity_go_live_at TIMESTAMPTZ,
    session_timeout_minutes INTEGER NOT NULL DEFAULT 30 CHECK (session_timeout_minutes > 0),
    source_version TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE page_classification_rules IS
  'Batch-only path classification input; rules are not a security detector.';
COMMENT ON TABLE country_demand_identity_config IS
  'Contract for first-party visitor identity rollout and cold-start boundary.';
