from app.core.country_demand import aggregate_country_demand


def test_weighted_sessions_keep_counts_and_exclude_unknown_from_weight():
    events = [
        {"country_code": "DE", "session_id": "q", "traffic_status": "qualified", "traffic_validity_score": 0.92, "validity_confidence": 0.9},
        {"country_code": "DE", "session_id": "s", "traffic_status": "suspect", "traffic_validity_score": 0.58, "validity_confidence": 0.6},
        {"country_code": "DE", "session_id": "x", "traffic_status": "excluded", "traffic_validity_score": 0.1, "validity_confidence": 1.0},
        {"country_code": "DE", "session_id": "u", "traffic_status": "unknown", "traffic_validity_score": None, "validity_confidence": 0.0},
    ]
    result = aggregate_country_demand(events, [], config=None)["countries"][0]
    assert result["raw_sessions"] == 4
    assert result["qualified_sessions_count"] == 1
    assert result["suspect_sessions_count"] == 1
    assert result["excluded_sessions_count"] == 1
    assert result["unknown_sessions_count"] == 1
    assert result["weighted_qualified_sessions"] == 1.5
    assert result["evidence_coverage"] == 0.75
    assert result["weighted_qualified_sessions"] <= result["qualified_sessions_count"] + result["suspect_sessions_count"]


def test_validity_confidence_is_reported_but_not_multiplied_into_weight():
    result = aggregate_country_demand([
        {"country_code": "US", "session_id": "q", "traffic_status": "qualified", "traffic_validity_score": 0.8, "validity_confidence": 0.1},
    ], [], config=None)["countries"][0]
    assert result["weighted_qualified_sessions"] == 0.8
    assert result["avg_validity_confidence"] == 0.1
