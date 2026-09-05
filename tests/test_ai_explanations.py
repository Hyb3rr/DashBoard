from app.routers import ai_explanations


def test_explain_request_returns_job_without_running_model(monkeypatch):
    class FakeRepository:
        def create_or_get(self, case_id, fingerprint):
            assert (case_id, fingerprint) == ("case_1", "fp_1")
            return {"job_id": "job_1", "case_id": case_id, "evidence_fingerprint": fingerprint, "status": "pending"}

    monkeypatch.setattr(ai_explanations, "AiExplainJobRepository", FakeRepository)
    response = ai_explanations.request_explanation("case_1", ai_explanations.ExplainRequest(evidence_fingerprint="fp_1"))
    assert response == {"job_id": "job_1", "case_id": "case_1", "evidence_fingerprint": "fp_1", "status": "pending", "accepted": True}


def test_explain_request_rejects_blank_identity():
    from fastapi import HTTPException
    import pytest

    with pytest.raises(HTTPException) as error:
        ai_explanations.request_explanation(" ", ai_explanations.ExplainRequest(evidence_fingerprint="fp_1"))
    assert error.value.status_code == 400


def test_get_job_exposes_validated_result_only(monkeypatch):
    class FakeRepository:
        def get(self, job_id):
            assert job_id == "job_1"
            return {"job_id": job_id, "case_id": "case_1", "evidence_fingerprint": "fp_1", "status": "completed", "validation_status": "validated", "analysis_json": {"summary": "ok"}, "validation_json": {"grounded": True}, "provenance_json": {"model": "local"}, "failure_code": None}

    monkeypatch.setattr(ai_explanations, "AiExplainJobRepository", FakeRepository)
    response = ai_explanations.get_explanation_job("job_1")
    assert response["analysis"] == {"summary": "ok"}
    assert "raw_response" not in response


def test_get_job_hides_unvalidated_result(monkeypatch):
    class FakeRepository:
        def get(self, _):
            return {"job_id": "job_1", "case_id": "case_1", "evidence_fingerprint": "fp_1", "status": "failed", "validation_status": "timeout", "analysis_json": {"should": "hide"}}

    monkeypatch.setattr(ai_explanations, "AiExplainJobRepository", FakeRepository)
    response = ai_explanations.get_explanation_job("job_1")
    assert response["analysis"] is None
    assert response["validation"] is None
