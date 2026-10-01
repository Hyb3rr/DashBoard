from app.core import metrics
from app.core.intelligence import classify_ip
from app.core.shadow_scoring import family_max_behavior_score
from app.services.classification import classify_with_rollout_metrics


def test_family_max_uses_recent_rule_families_and_preserves_unmapped_rules():
    detections = [
        {"id": "WEB-4XX-001", "points": 15},
        {"id": "WEB-BOT-001", "points": 10},
        {"id": "WEB-SCAN-001", "points": 20},
        {"id": "WEB-SENSITIVE-001", "points": 50},
        {"id": "WEB-BRUTE-001", "points": 8},
        {"id": "WEB-FUTURE-001", "points": 7},
    ]

    assert family_max_behavior_score(detections) == 80


def test_runtime_uses_family_max_and_records_score_delta_against_v1():
    metrics.reset()
    profile = {"is_tor": False, "is_proxy": False, "is_vpn": False, "is_hosting": False}
    observation = {
        "recent_behavior_score": 25,
        "recent_requests": 12,
        "recent_sensitive_probe_requests": 0,
        "recent_behavior_evidence": ["A — test rules fired"],
        "detections_recent": [
            {"id": "WEB-4XX-001", "points": 15},
            {"id": "WEB-BOT-001", "points": 10},
        ],
        # Other windows are intentionally different and must not enter the shadow.
        "detections_1h": [{"id": "WEB-SENSITIVE-001", "points": 50}],
        "detections_24h": [{"id": "WEB-SCAN-001", "points": 40}],
    }

    expected = classify_ip(profile, observation, {}, None)
    actual = classify_with_rollout_metrics(profile, observation, {}, None)
    metrics_state = metrics.snapshot()

    assert actual["score_breakdown"]["behavior_a"] == 15
    assert actual["confidence"] == expected["confidence"]
    assert actual["confidence_factors"] == expected["confidence_factors"]
    assert observation["classification_scoring_mode"] == "family_max"
    assert observation["classification_behavior_score"] == 15
    assert metrics_state["counters"]["scoring.family_max.observations"] == 1
    assert metrics_state["counters"]["scoring.family_max.v1_behavior_points"] == 25
    assert metrics_state["counters"]["scoring.family_max.shadow_behavior_points"] == 15
    assert metrics_state["counters"]["scoring.family_max.delta_negative_samples"] == 1
    assert metrics_state["counters"]["scoring.family_max.delta_negative_points"] == 10
    assert metrics_state["gauges"]["scoring.family_max.last_delta"] == -10


def test_runtime_family_max_preserves_hard_sensitive_critical_behavior():
    profile = {}
    observation = {
        "recent_behavior_score": 0,
        "recent_requests": 3,
        "recent_sensitive_probe_requests": 1,
        "recent_behavior_evidence": [],
        "detections_recent": [{"id": "WEB-SENSITIVE-001", "points": 50}],
    }

    expected = classify_ip(profile, observation, {}, None)
    actual = classify_with_rollout_metrics(profile, observation, {}, None)

    assert actual["label"] == "critical"
    assert expected["label"] == "critical"
    assert actual["score_breakdown"]["behavior_a"] == 50


def test_family_max_changes_only_behavior_score_and_preserves_confidence():
    profile = {
        "organization": "Example Network",
        "organization_confidence": 95,
        "is_hosting": False,
        "is_tor": True,
        "country_code": "US",
    }
    observation = {
        "recent_behavior_score": 24,
        "recent_requests": 12,
        "recent_sensitive_probe_requests": 0,
        "recent_behavior_evidence": ["A — correlated 4xx rules"],
        "detections_recent": [
            {"id": "WEB-4XX-001", "points": 12},
            {"id": "WEB-BOT-001", "points": 12},
        ],
    }
    region = {"country_name": "United States", "conflict_indicators": [{"type": "interstate_war"}]}
    ai = {"ai_anomaly_score": 80, "windows_seen": 3, "anomalous_windows": 2, "confidence_level": "high"}

    v1 = classify_ip(profile, observation, region, ai)
    actual = classify_with_rollout_metrics(profile, observation, region, ai)

    assert actual["score_breakdown"] == {
        **v1["score_breakdown"],
        "behavior_a": 12,
    }
    assert (actual["score_breakdown"]["identity_b"], actual["score_breakdown"]["trust_c"],
            actual["score_breakdown"]["region_d"], actual["score_breakdown"]["ai_e"]) == (15, -20, 5, 8)
    assert actual["score"] == 20
    assert actual["label"] == "medium"
    assert actual["confidence"] == v1["confidence"]
    assert actual["confidence_factors"] == v1["confidence_factors"]


def test_family_max_preserves_hard_sensitive_critical_and_falls_back_if_detections_missing():
    metrics.reset()
    hard_sensitive = {
        "recent_behavior_score": 0,
        "recent_requests": 3,
        "recent_sensitive_probe_requests": 1,
        "detections_recent": [],
    }
    assert classify_with_rollout_metrics({}, hard_sensitive, {}, None)["label"] == "critical"

    missing_detections = {"recent_behavior_score": 20, "recent_requests": 10}
    expected = classify_ip({}, missing_detections, {}, None)
    assert classify_with_rollout_metrics({}, missing_detections, {}, None) == expected
    assert metrics.snapshot()["counters"]["scoring.family_max.mode_fallback_missing_detections"] == 1
