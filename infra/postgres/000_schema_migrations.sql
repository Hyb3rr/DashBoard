CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  filename TEXT NOT NULL UNIQUE,
  checksum_sha256 TEXT NOT NULL,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  status TEXT NOT NULL DEFAULT 'applied',
  CONSTRAINT schema_migrations_status_check CHECK (status IN ('applied', 'failed'))
);
