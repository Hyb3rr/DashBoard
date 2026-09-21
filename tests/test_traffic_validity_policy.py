from app.core.traffic_validity import evaluate_traffic_validity


def test_known_scanner_is_hard_excluded():
    result = evaluate_traffic_validity({"is_scanner": True})
    assert result["traffic_status"] == "excluded"
    assert result["traffic_validity_score"] == 0.0
    assert result["validity_reasons"] == ["known_scanner"]


def test_human_browser_evidence_qualifies_without_engagement_or_geo():
    result = evaluate_traffic_validity({"cf_bot_score": 86, "cf_js_detection_passed": True, "geo_conflict": True, "engagement_seconds": 0})
    assert result["traffic_status"] == "qualified"
    assert result["traffic_validity_score"] == 0.9
    assert result["validity_confidence"] == 0.6667


def test_vpn_is_soft_negative_and_mobile_is_neutral():
    result = evaluate_traffic_validity({"cf_bot_score": 86, "is_vpn": True, "is_mobile": True})
    assert result["traffic_status"] == "suspect"
    assert result["traffic_validity_score"] == 0.65
    assert "mobile_network_neutral" in result["validity_reasons"]


def test_missing_evidence_is_unknown_not_clean():
    result = evaluate_traffic_validity({})
    assert result == {
        "traffic_validity_score": None,
        "traffic_status": "unknown",
        "validity_confidence": 0.0,
        "validity_reasons": ["insufficient_validity_evidence"],
    }


def test_geo_and_engagement_do_not_change_validity():
    base = evaluate_traffic_validity({"cf_bot_score": 86})
    changed = evaluate_traffic_validity({"cf_bot_score": 86, "geo_conflict": True, "engagement_seconds": 999, "pageviews": 20})
    assert changed == base
