from app.core.intelligence import classify_ip
from app.services.case_packets import build_case_packet


def _classification(score, requests=10, sensitive=0):
    return classify_ip(
        {},
        {
            "requests": requests,
            "behavior_score": score,
            "sensitive_probe_requests": sensitive,
        },
    )


def test_five_classification_tiers_follow_score_boundaries():
    assert _classification(0)["label"] == "good"
    assert _classification(9)["label"] == "good"
    assert _classification(10)["label"] == "low"
    assert _classification(29)["label"] == "low"
    assert _classification(30)["label"] == "medium"
    assert _classification(59)["label"] == "medium"
    assert _classification(60)["label"] == "critical"


def test_insufficient_traffic_remains_unknown_without_signal():
    assert _classification(0, requests=2)["label"] == "unknown"


def test_one_high_confidence_sensitive_request_is_not_unknown():
    result = _classification(65, requests=1, sensitive=1)
    assert result["label"] == "critical"


def test_case_packet_accepts_only_the_new_classification_vocabulary():
    for label in ("unknown", "good", "low", "medium", "critical"):
        packet = build_case_packet(
            "203.0.113.10",
            {"label": label, "score": 0},
            {"start": "", "end": ""},
            {},
            [],
        )
        assert packet["classification"]["label"] == label
