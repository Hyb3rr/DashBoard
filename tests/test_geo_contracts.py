import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_geo_resolution_schema_and_fixtures_are_present_and_versioned():
    schema = json.loads((ROOT / "schemas/geoip-resolution.schema.json").read_text())
    fixtures = json.loads((ROOT / "tests/fixtures/geo/geo_resolution_contracts.json").read_text())

    assert schema["$schema"].endswith("draft/2020-12/schema")
    assert {"normalizedSourceRecord", "validatedSourceRecord", "canonicalResolution"} <= set(schema["$defs"])
    assert len(fixtures) == 6
    assert {item["id"] for item in fixtures} == {
        "bg_sc_frankfurt", "non_independent_majority", "nearby_city_conflict",
        "sentinel_coordinate", "verified_geofeed", "complete_disagreement",
    }
    for item in fixtures:
        assert item["expected_country"] is None or len(item["expected_country"]) == 2
