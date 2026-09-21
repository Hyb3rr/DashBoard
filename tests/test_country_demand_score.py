from app.core.country_demand import aggregate_country_demand


def event(session, score, *, engaged=None, pageviews=None, key_events=None):
    return {"country_code": "DE", "session_id": session, "traffic_status": "qualified", "traffic_validity_score": score, "validity_confidence": 0.8, "engaged": engaged, "pageviews": pageviews, "key_event_count": key_events}


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
    assert result["demand_confidence"] <= result["engagement_evidence_coverage"]


def test_missing_engagement_does_not_create_high_quality_score():
    result = aggregate_country_demand([event("a", 0.9)], [])["countries"][0]
    assert result["engagement_quality_score"] is None
    assert result["engagement_evidence_coverage"] == 0.0
    assert "engagement coverage 0%" in result["demand_reason"]


def test_geo_fields_do_not_change_country_demand_score():
    base = aggregate_country_demand([event("a", 0.9, engaged=True, pageviews=2)], [])["countries"][0]
    geo = aggregate_country_demand([dict(event("a", 0.9, engaged=True, pageviews=2), geo_confidence=0.1, geo_conflict=True)], [])["countries"][0]
    assert geo["country_demand_score"] == base["country_demand_score"]
