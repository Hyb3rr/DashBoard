from app.services.geo_normalization import (
    normalize_geoip,
    normalize_geofeed,
    normalize_ip2region,
    normalize_rir,
    normalize_sapics_country,
)


def test_sapics_user_and_server_are_separate_normalized_records():
    user = normalize_sapics_country("user-country", "bg")
    server = normalize_sapics_country("server-country", "BG")
    assert user["source"] != server["source"]
    assert user["country_code"] == server["country_code"] == "BG"
    assert user["scope"] == "network_operational"
    assert user["derived_from"] == server["derived_from"] == "sapics_network_country"
    assert user["correlation_group"] == "sapics_network_country"


def test_sapics_runtime_source_identifiers_use_the_production_contract():
    user = normalize_sapics_country("user_country", "SG")
    server = normalize_sapics_country("server_country", "SG")
    assert user["source"] == "sapics:user_country"
    assert server["source"] == "sapics:server_country"
    assert user["derived_from"] == server["derived_from"] == "sapics_network_country"


def test_geolite_city_with_large_accuracy_radius_is_country_granularity():
    result = normalize_geoip("geolite2", {
        "country_code": "BG", "city": "Sofia", "latitude": 42.696,
        "longitude": 23.332, "accuracy_radius_km": 150,
    })
    assert result["coordinate_granularity"] == "country"
    assert result["source_type"] == "commercial_geoip"


def test_dbip_without_accuracy_does_not_claim_city_granularity():
    result = normalize_geoip("dbip", {
        "country_code": "SC", "city": None, "latitude": -4.62336, "longitude": 55.4522,
    })
    assert result["coordinate_granularity"] == "country"
    assert result["city"] is None


def test_context_registration_and_geofeed_scopes_are_separate():
    context = normalize_ip2region({"city": "Frankfurt", "region": "Hesse"})
    registration = normalize_rir("ripe", "UA")
    geofeed = normalize_geofeed("JP", city="Tokyo", verified=True)
    assert context["source_type"] == "context_validation"
    assert context["scope"] == "context_only"
    assert registration["source_type"] == "registration"
    assert registration["scope"] == "allocation_registration"
    assert geofeed["confidence_hint"] == 1.0
    assert geofeed["coordinate_granularity"] == "city"


def test_invalid_coordinates_are_normalized_to_unknown_not_clamped():
    result = normalize_geoip("dbip", {"country_code": "US", "latitude": 91, "longitude": 181})
    assert result["latitude"] is None
    assert result["longitude"] is None
    assert result["coordinate_granularity"] == "unknown"
