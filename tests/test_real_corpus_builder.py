from datetime import datetime, timezone

from scripts.ai.build_real_corpus import build_corpus


SNAPSHOT = datetime(2026, 9, 3, tzinfo=timezone.utc)


def traffic(*args):
    return {"total_requests": 10, "status_codes": {"4xx": 8}, "top_paths": [{"path": "/wp-login.php"}], "recent_requests": [{"method": "GET", "path": "/wp-login.php", "status": 404}]}


def row(ip="203.0.113.10"):
    return {"identity_ip": ip, "label": "medium", "classification_score": 42, "classification_confidence": 80, "observation_payload": {"requests": 10, "status_4xx": 8, "detections_24h": [{"id": "WEB-4XX-001", "name": "Repeated client errors", "points": 15, "evidence": "4xx ratio above 50 percent", "severity": "medium"}]}}


def test_builder_is_deterministic_and_bounded():
    first = build_corpus([row()], traffic, SNAPSHOT)
    second = build_corpus([row()], traffic, SNAPSHOT)
    assert first == second
    assert first["manifest"]["packet_count"] == 1
    assert first["manifest"]["selection_reason"]["203.0.113.10"] == ["classification_medium", "rule_fired", "high_404"]
    assert first["cases"][0]["evidence"][0]["type"] == "rule"


def test_builder_does_not_assign_ground_truth_or_call_ai():
    packet = build_corpus([row("203.0.113.11")], traffic, SNAPSHOT)["cases"][0]
    assert packet["classification"]["label"] == "medium"
    assert "ground_truth" not in packet
    assert "raw_headers" not in packet
    assert "user_agent" not in packet
