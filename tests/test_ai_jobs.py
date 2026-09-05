import pytest

from app.db.ai_jobs import AiExplainJobRepository, deterministic_job_id


def test_job_id_is_stable_and_requires_identity():
    assert deterministic_job_id("case_1", "fp_1") == deterministic_job_id("case_1", "fp_1")
    assert deterministic_job_id("case_1", "fp_1").startswith("job_")
    with pytest.raises(ValueError):
        deterministic_job_id("", "fp_1")


def test_invalid_transition_is_rejected_before_database_access():
    with pytest.raises(ValueError):
        AiExplainJobRepository().transition("job_1", "completed", "running")


def test_transition_uses_compare_and_set(monkeypatch):
    class Result:
        def fetchone(self):
            return {"job_id": "job_1", "status": "running"}

    class Connection:
        def __init__(self): self.calls = []
        def execute(self, sql, params):
            self.calls.append((sql, params))
            return Result()

    class Context:
        def __init__(self, conn): self.conn = conn
        def __enter__(self): return self.conn
        def __exit__(self, *_): return False

    connection = Connection()
    monkeypatch.setattr("app.db.ai_jobs.transaction", lambda: Context(connection))
    row = AiExplainJobRepository().transition("job_1", "pending", "running")
    assert row["status"] == "running"
    assert "AND status=%s" in connection.calls[0][0]
    assert connection.calls[0][1] == ("job_1", "pending")


def test_completed_result_requires_running_job_and_persists_validated_payload(monkeypatch):
    class Result:
        def fetchone(self):
            return {"job_id": "job_1", "status": "completed", "validation_status": "validated"}

    class Connection:
        def __init__(self): self.calls = []
        def execute(self, sql, params): self.calls.append((sql, params)); return Result()

    class Context:
        def __init__(self, conn): self.conn = conn
        def __enter__(self): return self.conn
        def __exit__(self, *_): return False

    connection = Connection()
    monkeypatch.setattr("app.db.ai_jobs.transaction", lambda: Context(connection))
    row = AiExplainJobRepository().persist_completed("job_1", {"summary": "ok"}, {"grounded": True}, {"model": "local"})
    assert row["validation_status"] == "validated"
    assert "status='running'" in connection.calls[0][0]


def test_failed_result_rejects_unknown_validation_status():
    with pytest.raises(ValueError):
        AiExplainJobRepository().persist_failed("job_1", "bad", "pending", "invalid_response", {})


def test_create_or_get_persists_optional_case_packet_without_overwrite(monkeypatch):
    class Result:
        def fetchone(self):
            return {"job_id": "job_1", "case_packet_json": {"case_id": "case_1"}}

    class Connection:
        def __init__(self): self.calls = []
        def execute(self, sql, params): self.calls.append((sql, params)); return Result()

    class Context:
        def __init__(self, conn): self.conn = conn
        def __enter__(self): return self.conn
        def __exit__(self, *_): return False

    connection = Connection()
    monkeypatch.setattr("app.db.ai_jobs.transaction", lambda: Context(connection))
    row = AiExplainJobRepository().create_or_get("case_1", "fp_1", {"case_id": "case_1"})
    insert_sql, insert_params = connection.calls[0]
    assert "case_packet_json" in insert_sql
    assert 'ON CONFLICT (case_id,evidence_fingerprint) DO NOTHING' in insert_sql
    assert '"case_id": "case_1"' in insert_params[3]
    assert row["case_packet_json"] == {"case_id": "case_1"}
