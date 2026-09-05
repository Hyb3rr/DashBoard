CREATE TABLE IF NOT EXISTS ai_explain_jobs (
  job_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  evidence_fingerprint TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  failure_code TEXT,
  CONSTRAINT ai_explain_jobs_status_check CHECK (status IN ('pending', 'running', 'completed', 'failed')),
  CONSTRAINT ai_explain_jobs_identity_unique UNIQUE (case_id, evidence_fingerprint),
  CONSTRAINT ai_explain_jobs_terminal_time_check CHECK (
    (status IN ('completed', 'failed') AND completed_at IS NOT NULL) OR
    (status IN ('pending', 'running') AND completed_at IS NULL)
  )
);

CREATE INDEX IF NOT EXISTS idx_ai_explain_jobs_pending
  ON ai_explain_jobs(status, requested_at)
  WHERE status = 'pending';
