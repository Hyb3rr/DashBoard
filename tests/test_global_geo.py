import ipaddress
import pytest

from app.core.net_utils import candidate_networks
from app.providers.global_geo import parse_geofeed, parse_rir_delegated
from app.providers import firehol, common
from app.db.pg_intelligence import GEO_RESOLUTION_RULESET, _resolve_city
from app.services import sapics_reader


def test_parse_rir_delegated_ipv4_and_ipv6():
    payload = "\n".join([
        "2|US|ipv4|198.51.100.0|256|20200101|allocated|",
        "2|DE|ipv6|2001:db8::|32|20200101|allocated|",
    ])
    rows = parse_rir_delegated(payload, "ARIN")
    assert {row["country_code"] for row in rows} == {"US", "DE"}
    assert any(row["network"] == "198.51.100.0/24" for row in rows)
    assert any(row["network"] == "2001:db8::/32" for row in rows)


def test_candidate_networks_are_bounded_and_canonical():
    ipv4 = candidate_networks(ipaddress.ip_address("198.51.100.7"))
    ipv6 = candidate_networks(ipaddress.ip_address("2001:db8::7"))
    assert len(ipv4) == 34
    assert len(ipv6) == 130
    assert "198.51.100.0/24" in ipv4
    assert "2001:db8::/32" in ipv6


def test_geofeed_normalizes_country_and_cidr():
    rows = parse_geofeed("198.51.100.0/24,us\n2001:db8::/32,DE\ninvalid,XX\n")
    assert rows == [
        {"network": "198.51.100.0/24", "country_code": "US"},
        {"network": "2001:db8::/32", "country_code": "DE"},
    ]


def test_geo_resolution_ruleset_invalidates_previous_cache_contract():
    assert GEO_RESOLUTION_RULESET == "geo-v5"


def test_country_resolution_uses_majority_without_marking_clear_winner_disputed(monkeypatch):
    countries = {"user_country": "NL", "server_country": "NL", "geolite2_country": "NL", "dbip_country": "NL", "iptoasn_country": "FR"}
    monkeypatch.setattr(sapics_reader, "_country", lambda name, ip: countries[name])
    monkeypatch.setattr(sapics_reader, "_city", lambda name, ip: {"country_code": "NL", "city": "Amsterdam", "latitude": 52.37, "longitude": 4.89})
    monkeypatch.setattr(sapics_reader, "_asn", lambda name, ip: None)

    result = sapics_reader.lookup("198.51.100.7")

    assert result["country"]["value"] == "NL"
    assert result["country"]["status"] == "resolved_with_conflict"
    assert result["country"]["conflict_severity"] == "low"
    assert result["country"]["agreement"] == {"NL": 4, "FR": 1}


def test_city_unknown_is_not_selected_when_coordinates_conflict(monkeypatch):
    countries = {name: "US" for name in ("user_country", "server_country", "geolite2_country", "dbip_country", "iptoasn_country")}
    cities = {
        "geolite2_city": {"country_code": "US", "city": None, "latitude": 37.751, "longitude": -97.822},
        "dbip_city": {"country_code": "US", "city": "Buffalo", "latitude": 42.893, "longitude": -78.875},
    }
    monkeypatch.setattr(sapics_reader, "_country", lambda name, ip: countries[name])
    monkeypatch.setattr(sapics_reader, "_city", lambda name, ip: cities[name])
    monkeypatch.setattr(sapics_reader, "_asn", lambda name, ip: None)

    result = sapics_reader.lookup("216.144.229.199")

    assert result["country"]["value"] == "US"
    assert result["city"]["value"] is None
    assert result["city"]["status"] == "disputed"
    assert result["city"]["coordinate_conflict"] is True
    assert result["city"]["latitude"] is None
    assert result["city"]["longitude"] is None


def test_vietnam_city_and_district_names_with_same_parent_are_normalized(monkeypatch):
    countries = {name: "VN" for name in ("user_country", "server_country", "geolite2_country", "dbip_country", "iptoasn_country")}
    cities = {
        "geolite2_city": {
            "country_code": "VN", "city": "Ho Chi Minh City", "state": "Ho Chi Minh",
            "latitude": 10.7769, "longitude": 106.7009,
        },
        "dbip_city": {
            "country_code": "VN", "city": "Quan Tan Phu", "state": "Ho Chi Minh City (HCMC)",
            "latitude": 10.80, "longitude": 106.72,
        },
    }
    monkeypatch.setattr(sapics_reader, "_country", lambda name, ip: countries[name])
    monkeypatch.setattr(sapics_reader, "_city", lambda name, ip: cities[name])
    monkeypatch.setattr(sapics_reader, "_asn", lambda name, ip: None)

    result = sapics_reader.lookup("198.51.100.9")

    assert result["city"]["value"] == "Ho Chi Minh City"
    assert result["city"]["status"] == "resolved"
    assert result["city"]["same_vietnam_parent"] is True
    assert result["city"]["conflict"] is False
    assert result["city"]["candidates"]["dbip_city"]["city"] == "Ho Chi Minh City"
    assert result["city"]["candidates"]["dbip_city"]["raw_city"] == "Quan Tan Phu"


def test_vietnam_city_names_with_different_parent_regions_remain_disputed():
    result = sapics_reader._city_consensus({
        "geolite2_city": {
            "country_code": "VN", "city": "Ho Chi Minh City", "state": "Ho Chi Minh",
            "latitude": 10.7769, "longitude": 106.7009,
        },
        "dbip_city": {
            "country_code": "VN", "city": "Bien Hoa", "state": "Dong Nai",
            "latitude": 10.95, "longitude": 106.82,
        },
    })

    assert result["same_vietnam_parent"] is False
    assert result["status"] == "disputed"


def test_unknown_city_coordinates_remain_only_as_vendor_fallback_candidates(monkeypatch):
    countries = {name: "BG" for name in ("user_country", "server_country", "geolite2_country", "dbip_country", "iptoasn_country")}
    cities = {
        "geolite2_city": {"country_code": "BG", "city": "Unknown", "latitude": 42.6960, "longitude": 23.3320},
        "dbip_city": {"country_code": "BG", "city": None, "latitude": 42.6960, "longitude": 23.3320},
    }
    monkeypatch.setattr(sapics_reader, "_country", lambda name, ip: countries[name])
    monkeypatch.setattr(sapics_reader, "_city", lambda name, ip: cities[name])
    monkeypatch.setattr(sapics_reader, "_asn", lambda name, ip: None)

    result = sapics_reader.lookup("216.144.229.199")

    assert result["city"]["value"] is None
    assert result["city"]["latitude"] is None
    assert result["city"]["coordinate_granularity"] == "unknown"
    assert result["city"]["candidates"]["dbip_city"]["is_likely_fallback_value"] is True


def test_pg_city_resolution_keeps_coordinates_but_not_untrusted_city():
    result = _resolve_city([
        {"source": "maxmind", "country_code": "US", "city": "Unknown", "latitude": 37.751, "longitude": -97.822},
        {"source": "dbip", "country_code": "US", "city": "Buffalo", "latitude": 42.893, "longitude": -78.875},
    ], "US")

    assert result["city"] is None
    assert result["city_status"] == "disputed"
    assert result["coordinate_conflict"] is True
    assert result["latitude"] is None
    assert result["longitude"] is None


def test_firehol_parser_ignores_headers_and_accepts_mixed_networks():
    assert common.parse_networks("""# header\nipset=example\n203.0.113.7\n198.51.100.0/24 ; metadata\n2001:db8::/32\n""") == [
        "203.0.113.7/32", "198.51.100.0/24", "2001:db8::/32"
    ]


def test_firehol_official_feed_extensions():
    assert firehol.list_url("firehol_proxies").endswith("/firehol_proxies.netset")
    assert firehol.list_url("firehol_webserver").endswith("/firehol_webserver.netset")
    assert firehol.list_url("dshield").endswith("/dshield.netset")
    assert firehol.list_url("dm_tor").endswith("/dm_tor.ipset")
    assert firehol.list_url("feodo").endswith("/feodo.ipset")


@pytest.mark.integration
def test_resolver_prefers_geofeed_and_marks_close_conflict():
    pytest.skip("Requires PostgreSQL geo resolver environment")


@pytest.mark.integration
def test_database_initialization_is_cached_per_path():
    pytest.skip("Requires PostgreSQL environment")


@pytest.mark.integration
def test_lookup_exposes_network_location_without_network_io():
    pytest.skip("Requires PostgreSQL environment")


@pytest.mark.integration
def test_firehol_proxy_snapshot_populates_privacy_networks():
    pytest.skip("Requires PostgreSQL environment")


@pytest.mark.integration
def test_firehol_disabled_upstream_feed_does_not_download():
    pytest.skip("Requires PostgreSQL environment")


@pytest.mark.integration
def test_az0_supports_list_key_paths_and_isolates_mirror_errors():
    pytest.skip("Requires PostgreSQL environment")


@pytest.mark.integration
def test_device_browser_zip_api_payload_is_extracted_and_cached():
    pytest.skip("Requires PostgreSQL environment")
