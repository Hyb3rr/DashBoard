CREATE TABLE IF NOT EXISTS alerts (
  id BIGSERIAL PRIMARY KEY,
  ip INET NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'critical')),
  reason_type TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
  evidence_fingerprint TEXT NOT NULL,
  previous_classification JSONB NOT NULL DEFAULT '{}'::jsonb,
  current_classification JSONB NOT NULL DEFAULT '{}'::jsonb,
  status TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'acknowledged', 'resolved')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  acknowledged_at TIMESTAMPTZ,
  resolved_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  dedupe_key TEXT NOT NULL UNIQUE
);

CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity_status ON alerts(severity, status, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_ip ON alerts(ip, created_at DESC, id DESC);
