from app.core.country_demand import aggregate_session_observations


def test_visitor_identity_is_weaker_than_session_identity():
    rows = aggregate_session_observations([{"visitor_id": "v1", "country_code": "US"}, {"visitor_id": "v1", "country_code": "US"}])
    assert len(rows) == 1
    assert rows[0]["identity_level"] == "visitor"
    assert rows[0]["request_count"] == 2


def test_explicit_geo_conflict_is_preserved_when_country_is_consistent():
    rows = aggregate_session_observations([
        {"session_id": "s1", "country_code": "DE", "geo_conflict": True},
        {"session_id": "s1", "country_code": "DE", "geo_conflict": None},
    ])
    assert rows[0]["geo_conflict"] is True
