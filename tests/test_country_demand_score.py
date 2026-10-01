from app.core.country_demand import CountryDemandConfig, aggregate_country_demand, build_country_opportunities


from datetime import datetime, timezone


def event(session, score, *, engaged=None, pageviews=None, key_events=None, event_time=None, validity_evidence=False):
    return {"country_code": "DE", "session_id": session, "traffic_status": "qualified", "traffic_validity_score": score, "validity_confidence": 0.8, "engaged": engaged, "pageviews": pageviews, "key_event_count": key_events, "event_time": event_time, "http_validity_evidence_present": validity_evidence}


def test_country_demand_uses_weighted_volume_and_keeps_confidence_separate():
    result = aggregate_country_demand([
        event("a", 0.9, engaged=True, pageviews=4, key_events=1),
        event("b", 0.8, engaged=False, pageviews=1, key_events=0),
    ], [event("old", 0.7, engaged=True, pageviews=2, key_events=0)])["countries"][0]
    assert result["weighted_qualified_sessions"] == 1.7
    assert result["demand_strength_score"] > 0
    assert result["engagement_quality_score"] is not None
    assert result["momentum_pct"] is not None
    assert 0 <= result["country_demand_score"] <= 100
    assert result["demand_confidence_method"] == "http_log_evidence_v1"
    assert result["demand_confidence"] > 0
    assert "not probability" in result["demand_reason"]


def test_missing_engagement_does_not_create_high_quality_score():
    result = aggregate_country_demand([event("a", 0.9)], [])["countries"][0]
    assert result["engagement_quality_score"] is None
    assert result["engagement_evidence_coverage"] is None
    assert result["demand_confidence"] > 0
    assert "HTTP log evidence confidence" in result["demand_reason"]


def test_geo_fields_do_not_change_country_demand_score():
    base = aggregate_country_demand([event("a", 0.9, engaged=True, pageviews=2)], [])["countries"][0]
    geo = aggregate_country_demand([dict(event("a", 0.9, engaged=True, pageviews=2), geo_confidence=0.1, geo_conflict=True)], [])["countries"][0]
    assert geo["country_demand_score"] == base["country_demand_score"]


def test_log_evidence_confidence_breakdown_uses_four_http_only_components():
    rows = [
        event("s1", .9, event_time=datetime(2026, 9, 1, tzinfo=timezone.utc), validity_evidence=True),
        event("s2", .8, event_time=datetime(2026, 9, 2, tzinfo=timezone.utc), validity_evidence=True),
        event("s3", .8, event_time=datetime(2026, 9, 2, tzinfo=timezone.utc), validity_evidence=True),
        {**event(None, .7, event_time=datetime(2026, 9, 7, tzinfo=timezone.utc), validity_evidence=True), "session_id": None, "visitor_id": None},
        {"country_code": "DE", "traffic_status": "unknown", "traffic_validity_score": None, "event_time": datetime(2026, 9, 7, tzinfo=timezone.utc)},
    ]
    result = aggregate_country_demand(rows, [], period="7d", config=CountryDemandConfig(min_sample_size=8))["countries"][0]
    components = result["demand_confidence_components"]

    assert components["sample_size"] == 4
    assert components["sample_threshold"] == 8
    assert components["http_observation_count"] == 5
    assert components["http_validity_evidence_count"] == 4
    assert components["sample_sufficiency"] == 50
    assert components["traffic_validity_coverage"] == 80
    assert components["identity_coverage"] == 75
    assert components["temporal_coverage"] == round(3 / 7 * 100, 2)
    assert result["demand_confidence"] == 0.6293


def test_missing_identity_and_timestamp_are_unknown_and_weights_renormalize():
    row = {**event(None, .9), "session_id": None, "visitor_id": None, "event_time": None}
    result = aggregate_country_demand([row], [], config=CountryDemandConfig(min_sample_size=1))["countries"][0]
    components = result["demand_confidence_components"]
    assert components["identity_coverage"] == 0
    assert components["temporal_coverage"] is None
    assert "temporal_coverage" not in components["weights"]


def test_temporal_coverage_changes_confidence_without_changing_demand_score():
    base = event("s1", .9, engaged=True, pageviews=2, event_time=datetime(2026, 9, 1, tzinfo=timezone.utc), validity_evidence=True)
    spread = [
        {**base, "event_time": datetime(2026, 9, day, tzinfo=timezone.utc)}
        for day in (1, 2, 3, 4)
    ]
    concentrated = [dict(base) for _ in range(4)]
    config = CountryDemandConfig(min_sample_size=1)
    spread_result = aggregate_country_demand(spread, [], period="7d", config=config)["countries"][0]
    concentrated_result = aggregate_country_demand(concentrated, [], period="7d", config=config)["countries"][0]
    assert spread_result["country_demand_score"] == concentrated_result["country_demand_score"]
    assert spread_result["demand_confidence_components"]["temporal_coverage"] > concentrated_result["demand_confidence_components"]["temporal_coverage"]


def test_opportunity_projection_preserves_http_confidence_provenance():
    components = {"sample_sufficiency": 50, "traffic_validity_coverage": 80}
    row = {
        "country_code": "DE", "qualified_requests": 4, "country_demand_score": 60,
        "demand_confidence": .62, "demand_confidence_method": "http_log_evidence_v1",
        "demand_confidence_components": components,
    }
    result = build_country_opportunities({"30d": {"countries": [row]}}, {"DE": {"market_score": 70}})["countries"][0]
    assert result["demand_confidence"] == .62
    assert result["demand_confidence_method"] == "http_log_evidence_v1"
    assert result["demand_confidence_components"] == components
