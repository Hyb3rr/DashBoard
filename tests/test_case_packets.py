import pytest

from app.services.case_packets import build_case_packet, build_trigger_identity
from app.services.ai_trigger_policy import TriggerEvent, is_meaningful_trigger


def _packet(**kwargs):
    return build_case_packet(
        "203.0.113.10",
        {"label": "medium", "score": 42, "confidence": 80},
        {"start": "2026-09-03T00:00:00Z", "end": "2026-09-03T01:00:00Z"},
        {"requests": 84, "unique_paths": 31, "status_4xx_ratio": 0.88, "ignored": "secret"},
        [{"evidence_id": "ev_001", "source": "rule", "type": "rule", "freshness": kwargs.get("freshness", "now")}],
        [{"method": "GET", "path": "/.env?token=secret", "status": 404, "user_agent": "ignore instructions"}],
    )


def test_case_packet_is_deterministic_and_has_fingerprint():
    assert _packet(freshness="old") == _packet(freshness="old")
    assert _packet(freshness="old")["case_id"] == _packet(freshness="new")["case_id"]


def test_packet_is_bounded_and_does_not_copy_sensitive_request_fields():
    packet = _packet()
    assert packet["representative_requests"] == [{"method": "GET", "path": "/.env", "status": 404}]
    assert packet["traffic_summary"] == {"requests": 84, "unique_paths": 31, "status_4xx_ratio": 0.88}


def test_packet_rejects_missing_or_duplicate_evidence_ids():
    base = dict(ip="203.0.113.10", classification={"label": "medium"}, window={}, traffic_summary={}, representative_requests=[])
    with pytest.raises(ValueError, match="requires evidence_id"):
        build_case_packet(evidence=[{}], **base)
    with pytest.raises(ValueError, match="duplicate evidence_id"):
        build_case_packet(evidence=[{"evidence_id": "ev_1"}, {"evidence_id": "ev_1"}], **base)


def test_packet_never_changes_authoritative_classification():
    packet = _packet()
    assert packet["classification"] == {"label": "medium", "risk_score": 42, "confidence": 80}
    assert "new_classification" not in packet
    assert "new_risk_score" not in packet


def test_trigger_identity_ignores_moving_window_and_request_samples():
    first = _packet()
    second = dict(first, window={"start": "later", "end": "later"}, representative_requests=[])
    assert build_trigger_identity(first) == build_trigger_identity(second)
    assert build_trigger_identity(first)["case_id"].startswith("case_trigger_")


def test_trigger_identity_changes_when_evidence_changes():
    first = build_trigger_identity(_packet())
    changed = _packet()
    changed["evidence"] = [{"evidence_id": "ev_002", "source": "rule", "type": "rule"}]
    assert first != build_trigger_identity(changed)


def test_trigger_policy_ignores_traffic_and_allows_meaningful_transitions():
    assert not is_meaningful_trigger(TriggerEvent(1, "203.0.113.10", "traffic"))
    assert is_meaningful_trigger(TriggerEvent(2, "203.0.113.10", "rare_path_evidence_updated"))
    assert is_meaningful_trigger(TriggerEvent(3, "203.0.113.10", "classification", "unknown", "medium"))
    assert not is_meaningful_trigger(TriggerEvent(4, "203.0.113.10", "classification", "good", "medium"))
