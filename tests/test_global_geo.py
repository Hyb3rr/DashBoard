import asyncio
import io
import json
import zipfile

from app.core import db
from app.core.enrichment import lookup
from app.core.geo_resolver import resolve_network_location
from app.providers.global_geo import parse_geofeed, parse_rir_delegated
from app.providers import firehol, common, device_browser_info
from app.providers import vpn_az0


def test_parse_rir_delegated_ipv4_and_ipv6():
    payload = "\n".join([
        "2|US|ipv4|198.51.100.0|256|20200101|allocated|",
        "2|DE|ipv6|2001:db8::|32|20200101|allocated|",
    ])
    rows = parse_rir_delegated(payload, "ARIN")
    assert {row["country_code"] for row in rows} == {"US", "DE"}
    assert any(row["network"] == "198.51.100.0/24" for row in rows)
    assert any(row["network"] == "2001:db8::/32" for row in rows)


def test_geofeed_normalizes_country_and_cidr():
    rows = parse_geofeed("198.51.100.0/24,us\n2001:db8::/32,DE\ninvalid,XX\n")
    assert rows == [
        {"network": "198.51.100.0/24", "country_code": "US"},
        {"network": "2001:db8::/32", "country_code": "DE"},
    ]


def test_resolver_prefers_geofeed_and_marks_close_conflict(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "geo.db")
    monkeypatch.setattr(db, "REGION_SEED_PATH", tmp_path / "missing.json")
    conn = db.connect()
    conn.execute("""INSERT INTO geo_prefixes
        (network,asn,organization,network_type,rir,registration_country,source,active)
        VALUES (?,?,?,?,?,?,?,1)""", ("8.8.8.0/24", "AS64500", "Example", "isp", "ARIN", "US", "rir:arin"))
    conn.execute("""INSERT INTO geo_location_observations
        (network,country_code,source,source_confidence,location_scope,observed_at)
        VALUES (?,?,?,?,?,?)""", ("8.8.8.0/24", "CA", "geofeed:test", 95, "network", "2026-01-01T00:00:00+00:00"))
    conn.commit()
    result = resolve_network_location(conn, "8.8.8.10", {"country_code": "US", "country": "United States"})
    assert result["country_code"] == "CA"
    assert result["confidence"] >= 90
    assert "geofeed:test" in result["sources"]
    conn.close()


def test_lookup_exposes_network_location_without_network_io(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "geo.db")
    monkeypatch.setattr(db, "REGION_SEED_PATH", tmp_path / "missing.json")
    conn = db.connect()
    conn.execute("""INSERT INTO geo_prefixes
        (network,asn,organization,network_type,registration_country,source,active)
        VALUES(?,?,?,?,?,?,1)""", ("8.8.8.0/24", "AS64500", "Example", "isp", "US", "rir:arin"))
    conn.commit()
    conn.close()
    result = asyncio.run(lookup("8.8.8.10"))
    assert result["country_code"] == "US"
    assert result["network_location"]["scope"] == "registration"
    assert result["location_confidence"] > 0


def test_firehol_proxy_snapshot_populates_privacy_networks(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "firehol.db")
    monkeypatch.setattr(db, "REGION_SEED_PATH", tmp_path / "missing.json")
    conn = db.connect()

    class Response:
        headers = {}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b"203.0.113.0/24\n"

    monkeypatch.setattr(common, "urlopen", lambda request, timeout: Response())
    result = firehol.refresh_list(conn, "firehol_proxies", url="https://example.test/proxies", cache_dir=tmp_path / "cache")
    assert result["records_upserted"] == 1
    row = conn.execute("SELECT kind,provider FROM privacy_networks WHERE source='firehol:firehol_proxies'").fetchone()
    assert dict(row) == {"kind": "proxy", "provider": "FireHOL"}
    conn.close()


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


def test_firehol_disabled_upstream_feed_does_not_download(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "firehol-disabled.db")
    monkeypatch.setattr(db, "REGION_SEED_PATH", tmp_path / "missing.json")
    conn = db.connect()
    result = firehol.refresh_list(conn, "zeus", cache_dir=tmp_path / "cache")
    assert result["status"] == "unavailable"
    assert result["records_upserted"] == 0
    conn.close()


def test_az0_supports_list_key_paths_and_isolates_mirror_errors(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "az0.db")
    monkeypatch.setattr(db, "REGION_SEED_PATH", tmp_path / "missing.json")
    manifest = {
        "providers": {
            "example": {
                "urls": ["https://bad.example/feed", "https://good.example/feed"],
                "ip_key": ["payload", "ips"],
            }
        }
    }

    class Response:
        def __init__(self, payload):
            self.payload = payload

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return json.dumps(self.payload).encode()

    calls = []

    def fake_urlopen(request, timeout):
        target = request.full_url
        calls.append(target)
        if "manifest.example" in target:
            return Response(manifest)
        if "bad.example" in target:
            raise OSError("mirror unavailable")
        return Response({"payload": {"ips": ["203.0.113.10", "203.0.113.10"]}})

    monkeypatch.setattr(vpn_az0, "urlopen", fake_urlopen)
    conn = db.connect()
    result = vpn_az0.refresh(conn, url="https://manifest.example/manifest")
    assert result["status"] == "partial"
    assert result["records_upserted"] == 1
    assert result["providers"]["example"]["status"] == "partial"
    assert conn.execute("SELECT COUNT(*) FROM privacy_networks WHERE source='az0_vpn_ip'").fetchone()[0] == 1
    assert calls == ["https://manifest.example/manifest", "https://bad.example/feed", "https://good.example/feed"]
    conn.close()


def test_device_browser_zip_api_payload_is_extracted_and_cached(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "device.db")
    monkeypatch.setattr(db, "REGION_SEED_PATH", tmp_path / "missing.json")
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as value:
        value.writestr("free_trial.csv", "ip,asn.asn,asn.name,asn.network,geo.countryCode,isDataCenter,isProxy,proxyType\n203.0.113.9,64500,Example ISP,203.0.113.0/24,US,True,True,residential\n")

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return archive.getvalue()

    monkeypatch.setattr(device_browser_info, "urlopen", lambda request, timeout: Response())
    conn = db.connect()
    result = device_browser_info.refresh(conn, url="https://example.test/export.csv.zip?api_key=test", cache=tmp_path / "snapshot.csv")
    assert result["records_upserted"] == 1
    assert (tmp_path / "snapshot.csv").read_text().startswith("ip,asn.asn")
    row = conn.execute("SELECT kind,proxy_type FROM privacy_networks WHERE source='device_browser'").fetchone()
    assert dict(row) == {"kind": "proxy", "proxy_type": "datacenter"}
    metadata = conn.execute("SELECT metadata_json FROM privacy_networks WHERE source='device_browser'").fetchone()["metadata_json"]
    assert '"organization": "Example ISP"' in metadata
    conn.close()
