from app.core.intelligence import classify_ip
from app.services.case_packets import build_case_packet


def _classification(score, requests=10, sensitive=0):
    """Build a classification result for a behavior-score value."""
    return classify_ip(
        {},
        {
            "requests": requests,
            "behavior_score": score,
            "sensitive_probe_requests": sensitive,
        },
    )


def test_five_classification_tiers_follow_score_boundaries():
    """Keep verdict transitions aligned with the established score thresholds."""
    assert _classification(0)["label"] == "good"
    assert _classification(9)["label"] == "good"
    assert _classification(10)["label"] == "low"
    assert _classification(29)["label"] == "low"
    assert _classification(30)["label"] == "medium"
    assert _classification(59)["label"] == "medium"
    assert _classification(60)["label"] == "critical"


def test_insufficient_traffic_remains_unknown_without_signal():
    """Keep low-volume traffic unclassified when no signal is present."""
    assert _classification(0, requests=2)["label"] == "unknown"


def test_one_high_confidence_sensitive_request_is_not_unknown():
    """Treat a single confirmed sensitive probe as critical behavior."""
    result = _classification(65, requests=1, sensitive=1)
    assert result["label"] == "critical"


def test_case_packet_accepts_only_the_new_classification_vocabulary():
    """Keep case packets compatible with all supported classification labels."""
    for label in ("unknown", "good", "low", "medium", "critical"):
        packet = build_case_packet(
            "203.0.113.10",
            {"label": label, "score": 0},
            {"start": "", "end": ""},
            {},
            [],
        )
        assert packet["classification"]["label"] == label


def test_score_groups_preserve_caps_gates_and_evidence_order():
    """Lock score-group math, behavior gates, and evidence ordering."""
    from app.core.intelligence import classify_ip

    result = classify_ip(
        {
            "organization": "Example Network",
            "organization_confidence": 80,
            "country_code": "VN",
            "is_tor": True,
            "is_proxy": True,
            "is_vpn": True,
        },
        {
            "requests": 12,
            "behavior_score": 99,
            "recent_requests": 12,
            "recent_behavior_score": 20,
            "recent_behavior_evidence": ["measured behavior"],
            "recent_sensitive_probe_requests": 0,
        },
        {
            "country_name": "Viet Nam",
            "conflict_indicators": [{"type": "civil_war", "severity": "high"}],
        },
        {"ai_anomaly_score": 80, "windows_seen": 3, "anomalous_windows": 2},
    )

    assert result["label"] == "medium"
    assert result["score"] == 38
    assert result["score_breakdown"] == {
        "behavior_a": 20,
        "identity_b": 25,
        "trust_c": -20,
        "region_d": 5,
        "ai_e": 8,
    }
    assert result["evidence"] == [
        "A — measured behavior",
        "B — Tor exit signal (+15)",
        "B — Proxy signal (+10)",
        "B — VPN signal (+8)",
        "B — identity contribution capped at +25",
        "C — stable attributed network with low behavior risk (-20)",
        "D — Region conflict severity high (+5)",
        "Region profile available for Viet Nam",
        "E — AI flagged 2 anomalous window(s) despite low rule-based score (+8)",
    ]
    assert result["score_explanations"]["final"] == "Final score is the sum of A+B+C+D+E with no clamp applied."
