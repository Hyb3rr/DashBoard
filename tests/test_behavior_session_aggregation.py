import pytest

from app.services.behavior_sessions import BehaviorEventIdentityConflict, aggregate_behavior_sessions


def test_aggregates_event_types_and_preserves_coverage_counters():
    rows = aggregate_behavior_sessions([
        {"event_id": "a", "event_time": "2026-09-11T10:00:00Z", "visitor_id": "v1", "session_id": "s1", "event_name": "page_view"},
        {"event_id": "b", "event_time": "2026-09-11T10:00:01Z", "visitor_id": "v1", "session_id": "s1", "event_name": "engagement", "engagement_ms": 1250},
        {"event_id": "c", "event_time": "2026-09-11T10:00:02Z", "visitor_id": "v1", "session_id": "s1", "event_name": "key_event", "key_event_name": "signup"},
    ])
    assert rows == [{
        "session_id": "s1", "visitor_id": "v1", "first_event_at": "2026-09-11T10:00:00Z", "last_event_at": "2026-09-11T10:00:02Z",
        "events_count": 3, "pageviews": 1, "engagement_seconds": 1.25, "key_event_count": 1, "key_event_names": ["signup"],
        "pageview_event_count": 1, "engagement_event_count": 1, "has_pageview": True, "has_engagement": True, "has_key_event": True,
        "identity_conflict": False, "assigned_country": None, "country_source": None, "geo_confidence": None, "geo_conflict": False,
        "network_evidence": {
            "cf_bot_score": None, "cf_js_detection_passed": None, "is_tor": None, "is_vpn": None,
            "is_proxy": None, "is_hosting": None, "is_mobile": None, "is_scanner": None,
        },
    }]


def test_same_event_id_is_not_counted_twice_on_replay():
    rows = aggregate_behavior_sessions([
        {"event_id": "a", "event_time": "2026-09-11T10:00:00Z", "visitor_id": "v1", "session_id": "s1", "event_name": "page_view"},
        {"event_id": "a", "event_time": "2026-09-11T10:00:00Z", "visitor_id": "v1", "session_id": "s1", "event_name": "page_view"},
    ])
    assert rows[0]["events_count"] == 1
    assert rows[0]["pageviews"] == 1


def test_physical_duplicate_is_counted_once_across_session_metrics():
    duplicate = {
        "event_id": "x",
        "event_time": "2026-09-11T10:00:00Z",
        "visitor_id": "v1",
        "session_id": "s1",
        "event_name": "engagement",
        "engagement_ms": 1250,
        "key_event_name": None,
    }
    key_event = {
        "event_id": "y",
        "event_time": "2026-09-11T10:00:01Z",
        "visitor_id": "v1",
        "session_id": "s1",
        "event_name": "key_event",
        "key_event_name": "signup",
    }

    rows = aggregate_behavior_sessions([duplicate, duplicate.copy(), key_event])

    assert rows[0]["events_count"] == 2
    assert rows[0]["engagement_seconds"] == 1.25
    assert rows[0]["key_event_count"] == 1
    assert rows[0]["key_event_names"] == ["signup"]


def test_same_event_id_server_evidence_winner_is_order_independent():
    first = {
        "event_id": "x", "event_time": "2026-09-11T10:00:00Z", "visitor_id": "v1", "session_id": "s1",
        "ingested_at": "2026-09-11T10:00:00.100Z", "payload_hash": "a",
        "event_name": "page_view", "country_source": "cloudflare", "cf_bot_score": 30,
    }
    retry = {**first, "ingested_at": "2026-09-11T10:00:00.900Z", "country_source": "geoip", "cf_bot_score": 80}

    forward = aggregate_behavior_sessions([first, retry])[0]
    reverse = aggregate_behavior_sessions([retry, first])[0]

    assert forward["country_source"] == reverse["country_source"]
    assert forward["network_evidence"] == reverse["network_evidence"]


def test_same_event_id_same_ingestion_time_uses_deterministic_tie_breaker():
    first = {
        "event_id": "x", "event_time": "2026-09-11T10:00:00Z", "ingested_at": "2026-09-11T10:00:00Z",
        "payload_hash": "a", "visitor_id": "v1", "session_id": "s1", "event_name": "page_view",
        "country_source": "cloudflare", "cf_bot_score": 30,
    }
    second = {**first, "country_source": "geoip", "cf_bot_score": 80}

    forward = aggregate_behavior_sessions([first, second])[0]
    reverse = aggregate_behavior_sessions([second, first])[0]

    assert forward == reverse


def test_same_event_id_different_payload_hash_is_explicit_conflict():
    first = {
        "event_id": "x", "event_time": "2026-09-11T10:00:00Z", "ingested_at": "2026-09-11T10:00:00Z",
        "payload_hash": "a", "visitor_id": "v1", "session_id": "s1", "event_name": "page_view",
    }
    second = {**first, "payload_hash": "b", "path": "/different"}

    with pytest.raises(BehaviorEventIdentityConflict, match="event_id=x"):
        aggregate_behavior_sessions([first, second])

    with pytest.raises(BehaviorEventIdentityConflict, match="event_id=x"):
        aggregate_behavior_sessions([second, first])


def test_aggregates_uint8_boolean_evidence_as_python_booleans():
    rows = aggregate_behavior_sessions([
        {
            "event_id": "a", "event_time": "2026-09-11T10:00:00Z", "visitor_id": "v1", "session_id": "s1",
            "event_name": "page_view", "geo_conflict": 1, "cf_js_detection_passed": 0,
            "is_tor": 1, "is_mobile": 0,
        },
    ])

    assert rows[0]["geo_conflict"] is True
    assert rows[0]["network_evidence"]["cf_js_detection_passed"] is False
    assert rows[0]["network_evidence"]["is_tor"] is True
    assert rows[0]["network_evidence"]["is_mobile"] is False


def test_identity_conflict_is_exposed_and_missing_session_is_ignored():
    rows = aggregate_behavior_sessions([
        {"event_id": "a", "event_time": "2026-09-11T10:00:00Z", "visitor_id": "v1", "session_id": "s1", "event_name": "page_view"},
        {"event_id": "b", "event_time": "2026-09-11T10:00:01Z", "visitor_id": "v2", "session_id": "s1", "event_name": "page_view"},
        {"event_id": "c", "event_time": "2026-09-11T10:00:02Z", "visitor_id": "v3", "session_id": None, "event_name": "page_view"},
    ])
    assert len(rows) == 1
    assert rows[0]["identity_conflict"] is True
    assert rows[0]["visitor_id"] == "v1"
