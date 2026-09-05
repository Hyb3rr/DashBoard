CREATE TABLE IF NOT EXISTS ai_trigger_cursors (
  consumer_name TEXT PRIMARY KEY,
  cursor_seq BIGINT NOT NULL DEFAULT 0,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT ai_trigger_cursors_seq_check CHECK (cursor_seq >= 0)
);
