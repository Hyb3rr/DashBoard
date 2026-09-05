CREATE TABLE IF NOT EXISTS ai_feature_settings (
  feature_key TEXT PRIMARY KEY,
  enabled BOOLEAN NOT NULL DEFAULT FALSE,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO ai_feature_settings (feature_key, enabled)
VALUES ('critical_alert_auto_explain', FALSE)
ON CONFLICT (feature_key) DO NOTHING;
