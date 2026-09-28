from app.db.pg_intelligence import _country_group, _resolve_city


def test_country_group_uses_deterministic_tie_break_and_source_order():
    """Break country-confidence ties consistently and sort source evidence."""
    rows = [
        {"country_code": "BB", "source_confidence": 80, "source": "z-source"},
        {"country_code": "AA", "source_confidence": 80, "source": "b-source"},
        {"country_code": "AA", "source_confidence": 80, "source": "a-source"},
    ]

    code, items = _country_group(rows)
    assert code == "AA"
    assert [item["source"] for item in items] == ["a-source", "b-source"]

    reversed_code, reversed_items = _country_group(list(reversed(rows)))
    assert reversed_code == code
    assert reversed_items == items


def test_city_resolution_prefers_maxmind_when_provider_names_agree():
    """Use MaxMind as the preferred city source when providers agree."""
    city = _resolve_city([
        {"source": "maxmind", "country_code": "SG", "city": "Singapore", "latitude": 1.35, "longitude": 103.82, "source_confidence": 90},
        {"source": "dbip", "country_code": "SG", "city": "Singapore", "latitude": 1.36, "longitude": 103.81, "source_confidence": 70},
    ], "SG")

    assert city["city"] == "Singapore"
    assert city["city_source"] == "maxmind"
    assert city["city_status"] == "resolved"
    assert city["coordinate_conflict"] is False


def test_city_resolution_marks_large_coordinate_disagreement():
    """Mark cities disputed when provider coordinates exceed the conflict threshold."""
    city = _resolve_city([
        {"source": "maxmind", "country_code": "US", "city": "Portland", "latitude": 45.5, "longitude": -122.7, "source_confidence": 90},
        {"source": "dbip", "country_code": "US", "city": "Portland", "latitude": 43.7, "longitude": -70.3, "source_confidence": 70},
    ], "US")

    assert city["city"] is None
    assert city["city_status"] == "disputed"
    assert city["coordinate_conflict"] is True
