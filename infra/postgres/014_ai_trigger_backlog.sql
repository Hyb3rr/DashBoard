CREATE TABLE IF NOT EXISTS ai_trigger_deferred (
  ip INET PRIMARY KEY,
  event_seq BIGINT NOT NULL,
  reason TEXT NOT NULL,
  old_label TEXT,
  new_label TEXT,
  queued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT ai_trigger_deferred_seq_check CHECK (event_seq >= 0)
);

CREATE INDEX IF NOT EXISTS idx_ai_trigger_deferred_order
  ON ai_trigger_deferred(event_seq, ip);
