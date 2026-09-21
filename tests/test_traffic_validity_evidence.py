import pytest

from app.core.traffic_validity import normalize_traffic_evidence, optional_bool


@pytest.mark.parametrize(
    ("value", "expected"),
    [(True, True), (False, False), (1, True), (0, False), ("1", True), ("0", False), (None, None)],
)
def test_optional_bool_preserves_bool_and_unknown_semantics(value, expected):
    assert optional_bool(value) is expected


def test_optional_bool_rejects_ambiguous_values():
    with pytest.raises(ValueError, match="invalid boolean-like value"):
        optional_bool("false")


def test_normalizes_available_evidence_into_stable_namespaces():
    evidence = normalize_traffic_evidence({
        "cf_bot_score": 86,
        "cf_js_detection_passed": True,
        "is_tor": False,
        "is_vpn": True,
        "is_mobile": False,
        "country_code": "DE",
        "geo_confidence": 0.55,
        "geo_conflict": True,
        "engagement_seconds": 24,
        "pageviews": 3,
        "key_event_count": 1,
    })
    assert evidence["bot_evidence"] == {"cf_bot_score": 86, "known_bot": None, "scanner": None}
    assert evidence["browser_evidence"]["js_detection_passed"] is True
    assert evidence["network_evidence"]["tor"] is False
    assert evidence["network_evidence"]["vpn"] is True
    assert evidence["geo_evidence"] == {"assigned_country": "DE", "geo_confidence": 0.55, "geo_conflict": True}
    assert evidence["engagement_evidence"]["key_event_count"] == 1


def test_missing_signals_are_unknown_not_clean():
    evidence = normalize_traffic_evidence({"country_code": "US"})
    assert evidence["bot_evidence"] == {"cf_bot_score": None, "known_bot": None, "scanner": None}
    assert all(value is None for value in evidence["browser_evidence"].values())
    assert all(value is None for value in evidence["network_evidence"].values())
    assert evidence["geo_evidence"]["geo_conflict"] is None
    assert "traffic_validity_score" not in evidence
    assert "traffic_status" not in evidence


def test_geo_and_engagement_are_evidence_only():
    evidence = normalize_traffic_evidence({
        "geo_conflict": True,
        "engagement_seconds": 120,
        "pageviews": 8,
    })
    assert evidence["geo_evidence"]["geo_conflict"] is True
    assert evidence["engagement_evidence"]["engagement_seconds"] == 120
    assert "validity_reasons" not in evidence
