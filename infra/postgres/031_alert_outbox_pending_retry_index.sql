-- Keep the outbox worker's pending/retryable scan bounded as history grows.
CREATE INDEX IF NOT EXISTS idx_alert_outbox_pending_retry
  ON alert_outbox (next_retry_at ASC, id ASC)
  WHERE status = 'pending';
