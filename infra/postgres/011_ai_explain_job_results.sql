ALTER TABLE ai_explain_jobs
  ADD COLUMN IF NOT EXISTS analysis_json JSONB,
  ADD COLUMN IF NOT EXISTS validation_json JSONB,
  ADD COLUMN IF NOT EXISTS provenance_json JSONB,
  ADD COLUMN IF NOT EXISTS validation_status TEXT NOT NULL DEFAULT 'pending',
  ADD COLUMN IF NOT EXISTS provider_status TEXT;

ALTER TABLE ai_explain_jobs
  DROP CONSTRAINT IF EXISTS ai_explain_jobs_validation_status_check;

ALTER TABLE ai_explain_jobs
  ADD CONSTRAINT ai_explain_jobs_validation_status_check
  CHECK (validation_status IN ('pending', 'validated', 'invalid', 'unsupported_evidence', 'unavailable', 'timeout'));

ALTER TABLE ai_explain_jobs
  DROP CONSTRAINT IF EXISTS ai_explain_jobs_completed_result_check;

ALTER TABLE ai_explain_jobs
  ADD CONSTRAINT ai_explain_jobs_completed_result_check
  CHECK (status <> 'completed' OR (analysis_json IS NOT NULL AND validation_status = 'validated'));
