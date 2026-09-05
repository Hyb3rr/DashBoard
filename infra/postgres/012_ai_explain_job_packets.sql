ALTER TABLE ai_explain_jobs
  ADD COLUMN IF NOT EXISTS case_packet_json JSONB;
