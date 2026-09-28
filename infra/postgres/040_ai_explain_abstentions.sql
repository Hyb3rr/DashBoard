ALTER TABLE ai_explain_jobs
  DROP CONSTRAINT IF EXISTS ai_explain_jobs_status_check;

ALTER TABLE ai_explain_jobs
  ADD CONSTRAINT ai_explain_jobs_status_check
  CHECK (status IN ('pending', 'running', 'completed', 'failed', 'abstained'));

ALTER TABLE ai_explain_jobs
  DROP CONSTRAINT IF EXISTS ai_explain_jobs_terminal_time_check;

ALTER TABLE ai_explain_jobs
  ADD CONSTRAINT ai_explain_jobs_terminal_time_check
  CHECK (
    (status IN ('completed', 'failed', 'abstained') AND completed_at IS NOT NULL) OR
    (status IN ('pending', 'running') AND completed_at IS NULL)
  );

ALTER TABLE ai_explain_jobs
  DROP CONSTRAINT IF EXISTS ai_explain_jobs_validation_status_check;

ALTER TABLE ai_explain_jobs
  ADD CONSTRAINT ai_explain_jobs_validation_status_check
  CHECK (validation_status IN (
    'pending', 'validated', 'invalid', 'unsupported_evidence', 'unavailable',
    'timeout', 'too_large', 'abstained'
  ));

ALTER TABLE ai_explain_jobs
  ADD CONSTRAINT ai_explain_jobs_abstained_result_check
  CHECK (
    status <> 'abstained' OR
    (validation_status = 'abstained' AND provider_status = 'not_called' AND analysis_json IS NULL)
  );
