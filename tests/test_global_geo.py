import ipaddress
import pytest

from app.core.net_utils import candidate_networks
from app.providers.global_geo import parse_geofeed, parse_rir_delegated
from app.providers import firehol, common


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
