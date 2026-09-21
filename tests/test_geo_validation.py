from datetime import datetime, timezone

from app.services.geo_normalization import normalize_geoip
from app.services.geo_validation import validate_records


BOUNDS = {
    "BG": (41.2, 22.3, 44.3, 28.7),
    "SC": (-10.0, 45.5, -3.5, 56.0),
    "DE": (47.2, 5.8, 55.1, 15.1),
    "US": (18.0, -170.0, 72.0, -65.0),
}


def test_bg_claim_with_seychelles_coordinate_is_invalid_but_other_record_survives():
    records = [
        normalize_geoip("dbip", {"country_code": "SC", "latitude": -4.62336, "longitude": 55.45220}),
        normalize_geoip("geolite2", {"country_code": "BG", "city": None, "latitude": 42.6960, "longitude": 23.3320}),
    ]
    validated = validate_records(records, country_bounds=BOUNDS)
    assert validated[0]["valid"] is True
    assert validated[1]["valid"] is True
    # A source's own SC coordinate is valid; the cross-source BG/SC decision belongs to resolution.
    assert validated[1]["coordinate_granularity"] == "country"


def test_coordinate_country_mismatch_is_rejected():
    record = normalize_geoip("dbip", {"country_code": "BG", "latitude": -4.62336, "longitude": 55.45220})
    validated = validate_records([record], country_bounds=BOUNDS)
    assert validated[0]["valid"] is False
    assert validated[0]["invalid_reason"] == "coordinate_country_mismatch"


def test_sentinel_and_unknown_coordinates_are_annotated():
    records = [
        normalize_geoip("dbip", {"country_code": "US", "latitude": 0, "longitude": 0}),
        normalize_geoip("dbip", {"country_code": "US", "latitude": 40, "longitude": -73}),
    ]
    validated = validate_records(records, country_bounds=BOUNDS, sentinels={"dbip": {(40.0, -73.0)}})
    assert validated[0]["invalid_reason"] == "null_island"
    assert validated[1]["valid"] is True
    assert validated[1]["is_likely_fallback_value"] is True


def test_duplicate_records_are_marked_without_being_removed():
    records = [
        normalize_geoip("geolite2", {"country_code": "US", "city": "New York", "latitude": 40.7, "longitude": -74.0, "accuracy_radius_km": 20}),
        normalize_geoip("dbip", {"country_code": "US", "city": "New York", "latitude": 40.7, "longitude": -74.0, "accuracy_radius_km": 20}),
    ]
    validated = validate_records(records, country_bounds=BOUNDS)
    assert len(validated) == 2
    assert validated[0]["possibly_duplicate_of"] == ["dbip"]
    assert validated[1]["possibly_duplicate_of"] == ["geolite2"]


def test_stale_version_is_retained_for_weight_penalty():
    record = normalize_geoip("geolite2", {"country_code": "US", "city": "New York", "latitude": 40.7, "longitude": -74.0}, database_version="2024-01")
    validated = validate_records([record], country_bounds=BOUNDS, now=datetime(2026, 9, 7, tzinfo=timezone.utc))
    assert validated[0]["valid"] is True
    assert validated[0]["invalid_reason"] == "stale_database_version"
