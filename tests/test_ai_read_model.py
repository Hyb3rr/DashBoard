from app.routers import ip_state
from app.routers import ip_detail
import pytest


def _row(ip="203.0.113.10"):
    return {
        "ip": ip,
        "observation_payload": {"requests": 10, "recent_behavior_score": 0},
        "label": "good",
        "classification_score": 0,
        "classification_confidence": 70,
        "disposition": "new",
    }


def test_read_model_exposes_persisted_ai_without_reclassifying(monkeypatch):
    ai = {
        "ip": "203.0.113.10",
        "ai_anomaly_score": 90,
        "windows_seen": 4,
        "anomalous_windows": 2,
        "score_reason": "new_traffic",
        "model_version": "model-1",
    }

    class FakeState:
        def page(self, *args, **kwargs):
            return {"rows": [_row()], "total": 1, "cursor": 4}

    class FakeAi:
        def scores(self, ips):
            assert list(ips) == ["203.0.113.10"]
            return [ai]

    monkeypatch.setattr(ip_state, "StateRepository", FakeState)
    monkeypatch.setattr(ip_state, "AiRepository", FakeAi)
    monkeypatch.setattr(
        ip_state,
        "classify_ip",
        lambda profile, observation, region, ai_profile: (
            assert_no_ai(ai_profile) or {"label": "good", "score": 0, "confidence": 70}
        ),
    )

    result = ip_state.list_ips()
    assert result[0]["ai_profile"] == ai
    assert result[0]["ai_status"] == "ready"


def assert_no_ai(ai_profile):
    assert ai_profile is None
    return False


def test_missing_ai_result_is_pending_and_schema_stable(monkeypatch):
    class FakeState:
        def page(self, *args, **kwargs):
            return {"rows": [_row("203.0.113.11")], "total": 1, "cursor": 5}

    class FakeAi:
        def scores(self, ips):
            return []

    monkeypatch.setattr(ip_state, "StateRepository", FakeState)
    monkeypatch.setattr(ip_state, "AiRepository", FakeAi)
    result = ip_state.list_ips()
    item = result[0]
    assert item["ai_profile"] == {}
    assert item["ai_status"] == "pending"
    assert "ai_anomaly_score" not in item["ai_profile"]


def test_read_api_does_not_trigger_ai_cycle(monkeypatch):
    calls = []

    class FakeState:
        def page(self, *args, **kwargs):
            return {"rows": [_row()], "total": 1, "cursor": 6}

    class FakeAi:
        def scores(self, ips):
            return []

    monkeypatch.setattr(ip_state, "StateRepository", FakeState)
    monkeypatch.setattr(ip_state, "AiRepository", FakeAi)
    monkeypatch.setattr("app.ai.detector.score_cycle", lambda *args, **kwargs: calls.append("score"))
    monkeypatch.setattr("app.ai.detector.train_model", lambda *args, **kwargs: calls.append("train"))
    ip_state.list_ips()
    assert calls == []


@pytest.mark.asyncio
async def test_detail_api_reads_persisted_ai_result(monkeypatch):
    ai = {"ip": "127.0.0.1", "ai_anomaly_score": 72, "windows_seen": 3}

    class FakeState:
        def get(self, ip):
            assert ip == "127.0.0.1"
            return _row(ip)

    class FakeAi:
        def scores(self, ips):
            return [ai]

    monkeypatch.setattr(ip_detail, "StateRepository", FakeState)
    monkeypatch.setattr(ip_detail, "AiRepository", FakeAi)
    result = await ip_detail.ip_details("127.0.0.1")
    assert result["ai_profile"] == ai
    assert result["ai_status"] == "ready"


@pytest.mark.asyncio
async def test_detail_api_marks_missing_ai_result_pending(monkeypatch):
    class FakeState:
        def get(self, ip):
            return _row(ip)

    class FakeAi:
        def scores(self, ips):
            return []

    monkeypatch.setattr(ip_detail, "StateRepository", FakeState)
    monkeypatch.setattr(ip_detail, "AiRepository", FakeAi)
    result = await ip_detail.ip_details("127.0.0.1")
    assert result["ai_profile"] == {}
    assert result["ai_status"] == "pending"
