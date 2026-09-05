import os

import pytest

from app.ai.detector import MODEL_KEY
from app.db.repositories import AiRepository
from app.services import ai_runtime as runtime_module


def test_ai_runtime_refuses_overlapping_cycle(monkeypatch):
    class Cursor:
        def fetchone(self):
            return {"acquired": False}

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def execute(self, sql, params):
            return Cursor()

    monkeypatch.setattr(runtime_module.postgres, "connect", lambda: Connection())
    monkeypatch.setattr(runtime_module, "train_model", lambda _conn: pytest.fail("overlapping train"))
    monkeypatch.setattr(runtime_module, "score_cycle", lambda _conn: pytest.fail("overlapping score"))
    assert runtime_module.AiRuntime._run_cycle_sync() == {"status": "locked"}


@pytest.mark.integration
def test_persisted_ai_state_and_scores_are_consistent():
    if not os.getenv("POSTGRES_DSN"):
        pytest.skip("POSTGRES_DSN is required for the live acceptance check")
    state = AiRepository().state(MODEL_KEY)
    summary = AiRepository().summary()
    assert state and state["last_score_status"] == "scored"
    assert state["model_version"]
    assert summary["scored"] >= 0
    assert 0 <= summary["coverage"] <= 100
