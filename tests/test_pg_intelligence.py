from app.db.pg_intelligence import _country_group


def test_country_group_uses_deterministic_tie_break_and_source_order():
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
