CREATE TABLE IF NOT EXISTS enrichment_requests (
  id BIGSERIAL PRIMARY KEY,
  ip INET NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  claimed_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  attempts INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  CONSTRAINT enrichment_requests_status_check CHECK (status IN ('pending', 'processing', 'complete', 'failed')),
  CONSTRAINT enrichment_requests_ip_unique UNIQUE (ip)
);

CREATE INDEX IF NOT EXISTS enrichment_requests_pending_idx
  ON enrichment_requests(status, requested_at, id)
  WHERE status IN ('pending', 'processing');
