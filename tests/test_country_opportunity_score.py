from app.core.country_demand import build_country_opportunities


def test_low_demand_with_high_confidence_reduces_opportunity():
    row = build_country_opportunities({"30d": {"countries": [{"country_code": "US", "qualified_requests": 20, "country_demand_score": 20, "demand_confidence": 0.90}]}}, {"US": {"country_name": "United States", "market_score": 85}})["countries"][0]
    assert row["adjusted_demand_score"] == 23.0
    assert row["opportunity_score"] == 60.2
    assert row["opportunity_status"] == "WATCH"


def test_missing_demand_does_not_create_false_opportunity():
    row = build_country_opportunities({"30d": {"countries": [{"country_code": "EE", "qualified_requests": 1}]}}, {"EE": {"country_name": "Estonia", "market_score": 80}})["countries"][0]
    assert row["adjusted_demand_score"] is None
    assert row["opportunity_score"] is None
    assert row["opportunity_status"] == "WATCH"
