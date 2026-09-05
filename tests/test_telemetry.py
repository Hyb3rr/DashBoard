from app.core.telemetry import confidence_for_label, data_health


def test_data_health_normalizes_rule_coverage():
    assert data_health({"rule_coverage": True}, {}, {})["rule_coverage"] is True
    assert data_health({"rule_coverage": "true"}, {}, {})["rule_coverage"] is True
    assert data_health({"rule_coverage": False}, {}, {})["rule_coverage"] is False
    assert data_health({"rule_coverage": "false"}, {}, {})["rule_coverage"] is False
    assert data_health({"rule_coverage": "invalid"}, {}, {})["rule_coverage"] is False


def test_data_health_requires_valid_ai_level_for_completeness():
    complete = {"core_enrichment_status": "complete", "privacy_enrichment_status": "complete"}
    assert data_health({"rule_coverage": True}, complete, {"confidence_level": "high"})["complete"] is True
    assert data_health({"rule_coverage": True}, complete, {})["complete"] is False
    assert data_health({"rule_coverage": True}, complete, {"confidence_level": "unavailable"})["complete"] is False


def test_data_health_clamps_and_tolerates_invalid_ai_confidence():
    assert data_health({}, {}, {"confidence": -1, "confidence_level": "low"})["ai_confidence"] == 0
    assert data_health({}, {}, {"confidence": 101, "confidence_level": "low"})["ai_confidence"] == 100
    assert data_health({}, {}, {"confidence": "50", "confidence_level": "low"})["ai_confidence"] == 50
    assert data_health({}, {}, {"confidence": "false", "confidence_level": "low"})["ai_confidence"] == 0


def test_confidence_policy_remains_deterministic_and_bounded():
    health = {
        "core_enrichment_status": "complete",
        "privacy_enrichment_status": "complete",
        "ai_confidence_level": "high",
        "rule_coverage": True,
    }
    first = confidence_for_label("medium", health)
    assert first == confidence_for_label("medium", health)
    assert 0 <= first[0] <= 100
