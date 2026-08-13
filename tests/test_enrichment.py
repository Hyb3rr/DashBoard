import asyncio
import csv
from io import StringIO
import json

from app.core.enrichment import (
    _maxmind,
    _merge,
    _network_flags,
    _risk,
    _tor_exit_list,
    lookup,
)
from app.core.intelligence import classify_ip
from app.core.regions import market_score, normalise_conflict_indicators
from app.core.logs import import_apache_lines, parse_apache_combined
from app.tools.tor_refresh import refresh_tor_exit_list
from app.tools.calibration import csv_text, evaluate_csv


def test_risk_uses_local_signals():
    score, level, evidence = _risk({"is_proxy": True, "is_vpn": False, "is_hosting": True})
    assert score == 55
    assert level == "high"
    assert evidence == ["Proxy signal from local database", "Hosting/datacenter signal"]


def test_unknown_privacy_signals_are_null():
    flags = _network_flags("Example ISP", "Example ISP")
    assert flags["is_vpn"] is None
    assert flags["is_proxy"] is None


def test_tor_refresh_replaces_atomically_and_validates_payload(monkeypatch, tmp_path):
    output = tmp_path / "tor_exit_nodes.txt"
    output.write_text("1.1.1.1\n", encoding="utf-8")

    class Response:
        headers = {"ETag": '"abc"', "Last-Modified": "Wed, 01 Jan 2025 00:00:00 GMT"}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b"8.8.8.8\nnot-an-ip\n192.168.1.1\n"

    monkeypatch.setattr("app.tools.tor_refresh.urlopen", lambda request, timeout: Response())
    result = refresh_tor_exit_list(output, url="https://example.test/tor")
    assert result["status"] == "updated"
    assert output.read_text(encoding="utf-8") == "8.8.8.8\n"
    metadata = json.loads(output.with_suffix(".txt.meta.json").read_text(encoding="utf-8"))
    assert metadata["etag"] == '"abc"'


def test_tor_refresh_keeps_old_file_on_empty_response(monkeypatch, tmp_path):
    output = tmp_path / "tor_exit_nodes.txt"
    output.write_text("8.8.8.8\n", encoding="utf-8")

    class Response:
        headers = {}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b""

    monkeypatch.setattr("app.tools.tor_refresh.urlopen", lambda request, timeout: Response())
    result = refresh_tor_exit_list(output, url="https://example.test/tor")
    assert result["status"] == "failed"
    assert output.read_text(encoding="utf-8") == "8.8.8.8\n"


def test_calibration_export_and_evaluation(tmp_path):
    payload = csv_text([
        {"ip": "8.8.8.8", "classification": {"label": "good", "score": 0, "confidence": 65}, "country": "United States"},
        {"ip": "1.1.1.1", "classification": {"label": "bad", "score": 70, "confidence": 90}, "country": "Australia"},
    ])
    path = tmp_path / "calibration.csv"
    rows = list(csv.DictReader(StringIO(payload)))
    rows[0]["human_label"] = "good"
    rows[1]["human_label"] = "watch"
    output = StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)
    path.write_text(output.getvalue(), encoding="utf-8")
    result = evaluate_csv(path)
    assert result["labeled"] == 2
    assert result["accuracy"] == 0.5
    assert result["mismatches"][0]["ip"] == "1.1.1.1"


def test_field_merge_does_not_overwrite_existing_value():
    base, sources = {"country": "US"}, {"country": "MaxMind"}
    filled = _merge(base, {"country": "CA", "city": "Dallas"}, "Fallback", sources)
    assert filled == ["city"]
    assert base == {"country": "US", "city": "Dallas"}
    assert sources == {"country": "MaxMind", "city": "Fallback"}


def test_tor_exit_list_default_snapshot_is_active(monkeypatch):
    monkeypatch.delenv("TOR_EXIT_LIST_PATH", raising=False)
    result, errors, status = _tor_exit_list("8.8.8.8")
    assert status == "active"
    assert result["is_tor"] is False
    assert not errors


def test_maxmind_missing_package_is_reported(monkeypatch):
    from app.core import enrichment

    monkeypatch.setenv("MAXMIND_CITY_DB", "/tmp/does-not-matter.mmdb")
    monkeypatch.setenv("MAXMIND_ASN_DB", "/tmp/does-not-matter.mmdb")
    monkeypatch.setattr(enrichment.Path, "is_file", lambda self: True)

    real_import = __import__

    def fake_import(name, *args, **kwargs):
        if name == "geoip2.database":
            raise ImportError("missing")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", fake_import)
    data, errors, status = _maxmind("8.8.8.8")
    assert data == {}
    assert status == "failed"
    assert errors == ["MaxMind: geoip2 package is not installed"]


def test_lookup_non_public_address():
    result = asyncio.run(lookup("127.0.0.1"))
    assert result["is_private"] is True
    assert result["core_enrichment_status"] == "complete"
    assert result["network_type"] == "private/non-public"


def test_lookup_uses_maxmind_when_available(monkeypatch):
    from app.core import enrichment

    monkeypatch.setattr(
        enrichment,
        "_maxmind",
        lambda ip: (
            {
                "country": "United States",
                "country_code": "US",
                "latitude": 37.4,
                "longitude": -122.1,
                "timezone": "America/Los_Angeles",
                "asn": "AS15169",
                "organization": "Google LLC",
            },
            [],
            "active",
        ),
    )
    result = asyncio.run(lookup("8.8.8.8"))
    assert result["country_code"] == "US"
    assert result["organization"] == "Google LLC"
    assert result["core_enrichment_status"] == "complete"
    assert result["provider_status"]["MaxMind City/ASN"]["status"] == "active"


def test_lookup_sets_is_tor_from_local_exit_list(monkeypatch, tmp_path):
    from app.core import enrichment

    tor_list = tmp_path / "tor.txt"
    tor_list.write_text("8.8.8.8\n")
    monkeypatch.setenv("TOR_EXIT_LIST_PATH", str(tor_list))
    monkeypatch.setattr(
        enrichment,
        "_maxmind",
        lambda ip: (
            {
                "country": "United States",
                "country_code": "US",
                "latitude": 37.4,
                "longitude": -122.1,
            },
            [],
            "active",
        ),
    )
    result = asyncio.run(lookup("8.8.8.8"))
    assert result["is_tor"] is True
    assert result["field_sources"]["is_tor"] == "Tor exit list"
    assert result["provider_status"]["Tor exit list"]["status"] == "active"


def test_lookup_reports_missing_local_geoip_configuration(monkeypatch):
    from app.core import enrichment

    monkeypatch.setattr(enrichment, "_maxmind", lambda ip: ({}, [], "not_configured"))
    result = asyncio.run(lookup("8.8.8.8"))
    assert result["core_enrichment_status"] == "failed"
    assert "No local GeoIP database configured" in result["provider_errors"][0]


def test_classify_ip_identity_only_is_capped_below_bad():
    result = classify_ip(
        {"is_tor": True, "is_proxy": True, "is_vpn": True, "is_hosting": True},
        {"behavior_score": 0, "requests": 20},
        {"country_name": "United States"},
    )
    assert result["label"] == "good"
    assert result["score_breakdown"]["identity_b"] == 25
    assert result["score"] == 25


def test_classify_ip_sensitive_probe_is_bad_without_identity_signal():
    result = classify_ip(
        {"country_code": "US"},
        {"behavior_score": 50, "sensitive_probe_requests": 1, "requests": 10},
    )
    assert result["label"] == "bad"
    assert result["score_breakdown"]["behavior_a"] == 50


def test_classify_ip_tor_and_probe_keeps_identity_cap():
    result = classify_ip(
        {"is_tor": True, "is_proxy": True, "is_vpn": True},
        {"behavior_score": 50, "sensitive_probe_requests": 1, "requests": 10},
    )
    assert result["label"] == "bad"
    assert result["score_breakdown"]["identity_b"] == 25
    assert result["score"] == 75


def test_classify_ip_returns_good_for_low_risk_attributed_network():
    result = classify_ip(
        {
            "organization": "Example ISP",
            "organization_confidence": 85,
            "is_hosting": False,
            "effective_risk_score": 0,
            "country_code": "US",
        },
        {"behavior_score": 0, "requests": 10},
        {"country_name": "United States"},
    )
    assert result["label"] == "good"


def test_classify_ip_uses_conflict_context_as_watch_signal():
    result = classify_ip(
        {"effective_risk_score": 10, "country_code": "UA"},
        {"behavior_score": 1, "requests": 10},
        {"country_name": "Ukraine", "conflict_indicators": [{"value": "Active interstate war environment with material operational disruption risk"}]},
    )
    assert result["score"] == 6
    assert "region conflict severity high" in " ".join(result["evidence"]).lower()


def test_classify_ip_region_does_not_create_risk_without_behavior():
    result = classify_ip(
        {"country_code": "UA"},
        {"behavior_score": 0, "requests": 20},
        {"country_name": "Ukraine", "conflict_indicators": [{"value": "Active interstate war environment"}]},
    )
    assert result["label"] == "good"
    assert result["score"] == 0


def test_classify_ip_low_volume_without_signals_is_unknown():
    result = classify_ip({}, {"behavior_score": 0, "requests": 1})
    assert result["label"] == "unknown"


def test_market_score_uses_equal_capacity_and_demand_weights():
    result = market_score({"economic_indicators": [
        {"market_signal": "market_capacity", "market_tier": "very_high", "source": "Seed", "data_date": "2026-08-12"},
        {"market_signal": "demand_fit", "market_tier": "medium", "source": "Seed", "data_date": "2026-08-12"},
    ]})
    assert result["market_score"] == 75
    assert result["market_level"] == "very_high"
    assert [item["effect"] for item in result["market_evidence"]] == [50.0, 25.0]


def test_market_score_renormalises_missing_signal_and_handles_unknown():
    partial = market_score({"economic_indicators": [
        {"market_signal": "demand_fit", "market_tier": "high"},
    ]})
    unknown = market_score({"economic_indicators": [{"label": "Economy", "value": "Large"}]})
    assert partial["market_score"] == 75
    assert unknown["market_score"] is None
    assert unknown["market_level"] == "unknown"


def test_market_context_cannot_change_security_classification():
    profile = {"country_code": "US"}
    observation = {"behavior_score": 30, "requests": 10}
    base_region = {"country_name": "United States", "conflict_indicators": []}
    scored_region = {**base_region, **market_score({"economic_indicators": [
        {"market_signal": "market_capacity", "market_tier": "very_high"},
        {"market_signal": "demand_fit", "market_tier": "very_high"},
    ]})}
    assert classify_ip(profile, observation, base_region) == classify_ip(profile, observation, scored_region)


def test_conflict_normalisation_tolerates_missing_and_malformed_items():
    indicators = normalise_conflict_indicators([
        None,
        42,
        "Unstructured legacy note",
        {"type": "armed_conflict", "severity": "invalid", "source": "UCDP"},
    ])
    assert len(indicators) == 2
    assert indicators[0]["type"] == "unknown"
    assert indicators[0]["severity"] is None
    assert indicators[1]["severity"] is None


def test_legacy_numeric_conflict_severity_mapping():
    indicators = normalise_conflict_indicators([
        {"type": "legacy", "severity": 0},
        {"type": "legacy", "severity": 2},
        {"type": "legacy", "severity": 4},
        {"type": "legacy", "severity": 5},
    ])
    assert [item["severity"] for item in indicators] == ["low", "medium", "high", "critical"]


def test_parse_apache_combined():
    line = '83.149.9.216 - - [17/May/2015:10:05:03 +0000] "GET /wp-login.php HTTP/1.1" 404 123 "-" "curl/8.0"'
    event = parse_apache_combined(line)
    assert event["src_ip"] == "83.149.9.216"
    assert event["method"] == "GET"
    assert event["path"] == "/wp-login.php"
    assert event["status"] == 404


def test_import_apache_lines_builds_observations(tmp_path, monkeypatch):
    from app.core import db

    monkeypatch.setattr(db, "DB_PATH", tmp_path / "hub.db")
    conn = db.connect()
    lines = [
        '83.149.9.216 - - [17/May/2015:10:05:03 +0000] "GET /wp-login.php HTTP/1.1" 404 123 "-" "curl/8.0"',
        '83.149.9.216 - - [17/May/2015:10:05:03 +0000] "GET /wp-login.php HTTP/1.1" 404 123 "-" "curl/8.0"',
    ]
    result = import_apache_lines(conn, lines, source="test.log")
    conn.commit()
    obs = conn.execute("SELECT * FROM ip_observations WHERE ip = ?", ("83.149.9.216",)).fetchone()
    conn.close()

    assert result["parsed"] == 2
    assert result["inserted"] == 1
    assert result["duplicates"] == 1
    assert obs["requests"] == 1
    assert obs["status_4xx"] == 1
    assert obs["wp_login_requests"] == 1


def test_window_features_use_utc_minutes_and_separate_sensitive_login(tmp_path, monkeypatch):
    from app.core import db
    from app.ai.features import build_window_features

    monkeypatch.setattr(db, "DB_PATH", tmp_path / "hub.db")
    conn = db.connect()
    conn.executemany(
        """INSERT INTO events
           (source,line_hash,raw_line,timestamp,src_ip,method,path,status,bytes_sent,user_agent,imported_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        [
            ("t", "h1", "", "2026-08-13T00:00:01+00:00", "8.8.8.8", "POST", "/wp-login.php", 404, 100, "ua", "now"),
            ("t", "h2", "", "2026-08-13T00:00:30+00:00", "8.8.8.8", "GET", "/.env", 403, None, "ua", "now"),
            ("t", "h3", "", "2026-08-13T00:01:00+00:00", "8.8.8.8", "GET", "/", 200, 300, None, "now"),
        ],
    )
    frame = build_window_features(conn)
    conn.close()

    first = frame.iloc[0]
    assert len(frame) == 2
    assert first["requests"] == 2
    assert first["sensitive_hits"] == 1
    assert first["login_attempts"] == 1
    assert first["ratio_403"] == 0.5
    assert first["avg_request_interval"] == 29
    assert first["std_request_interval"] == 0


def test_ai_score_insufficient_data_clears_stale_snapshot(tmp_path, monkeypatch):
    from app.core import db
    from app.ai.detector import score_import

    monkeypatch.setattr(db, "DB_PATH", tmp_path / "hub.db")
    conn = db.connect()
    conn.execute(
        "INSERT INTO ip_ai_scores (ip,windows_seen,anomalous_windows,ai_anomaly_score,model_mode,scored_at) VALUES (?,?,?,?,?,?)",
        ("8.8.8.8", 100, 1, 90, "fit_per_import", "now"),
    )
    result = score_import(conn)
    assert result["status"] == "insufficient_data"
    assert conn.execute("SELECT COUNT(*) FROM ip_ai_scores").fetchone()[0] == 0
    conn.close()


def test_group_e_promotes_watch_but_cannot_create_bad():
    from app.core.intelligence import classify_ip

    result = classify_ip(
        {"is_tor": True, "is_proxy": True, "is_vpn": True, "is_hosting": True},
        {"behavior_score": 0, "requests": 20},
        {"conflict_indicators": [{"type": "civil_war", "severity": "high"}]},
        {"ai_anomaly_score": 70, "anomalous_windows": 1},
    )
    assert result["score_breakdown"]["ai_e"] == 8
    assert result["label"] == "watch"


def test_existing_db_migration_adds_new_columns(tmp_path, monkeypatch):
    from app.core import db
    import sqlite3

    monkeypatch.setattr(db, "DB_PATH", tmp_path / "hub.db")
    conn = sqlite3.connect(db.DB_PATH)
    conn.execute("CREATE TABLE ip_profiles (ip TEXT PRIMARY KEY, fetched_at TEXT NOT NULL)")
    conn.commit()
    conn.close()

    migrated = db.connect()
    columns = {row["name"] for row in migrated.execute("PRAGMA table_info(ip_profiles)").fetchall()}
    migrated.close()
    assert {"core_enrichment_status", "privacy_enrichment_status", "threat_enrichment_status", "provider_status_json", "field_sources_json"} <= columns


def test_region_profile_seed_loads(tmp_path, monkeypatch):
    from app.core import db

    seed_path = tmp_path / "region.seed.json"
    seed_path.write_text(json.dumps([
        {
            "country_code": "US",
            "country_name": "United States",
            "economic_indicators": [{"label": "Economy", "value": "Large", "source": "Seed", "data_date": "2026-08-12", "confidence": "high"}],
            "cultural_context": [{"label": "Language", "value": "English", "source": "Seed", "data_date": "2026-08-12", "confidence": "medium"}],
            "conflict_indicators": [{"label": "Conflict status", "value": "No active civil war", "source": "Seed", "data_date": "2026-08-12", "confidence": "medium"}],
            "sources": [{"name": "Seed", "type": "market-context"}],
            "updated_at": "2026-08-12T00:00:00+00:00"
        }
    ]))
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "hub.db")
    monkeypatch.setattr(db, "REGION_SEED_PATH", seed_path)
    conn = db.connect()
    profile = db.region_profile(conn, "US")
    conn.close()
    assert profile["country_name"] == "United States"
    assert profile["economic_indicators"]["indicators"]["economy"]["label"] == "Economy"


def test_region_conflict_indicator_is_normalised_with_type_and_severity(tmp_path, monkeypatch):
    from app.core import db

    seed_path = tmp_path / "region.seed.json"
    seed_path.write_text(json.dumps([{
        "country_code": "UA",
        "country_name": "Ukraine",
        "economic_indicators": [],
        "cultural_context": [],
        "conflict_indicators": [{"label": "Conflict", "value": "Active civil war environment", "source": "UCDP", "data_date": "2026-08-12", "confidence": "high"}],
        "sources": [{"name": "UCDP", "type": "conflict"}],
        "updated_at": "2026-08-12T00:00:00+00:00",
    }]))
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "hub.db")
    monkeypatch.setattr(db, "REGION_SEED_PATH", seed_path)
    conn = db.connect()
    profile = db.region_profile(conn, "UA")
    conn.close()
    indicator = profile["conflict_indicators"][0]
    assert indicator["type"] == "civil_war"
    assert indicator["severity"] == "critical"
    assert indicator["source"] == "UCDP"
    assert indicator["date"] == "2026-08-12"
    assert indicator["description"] == "Active civil war environment"
    assert indicator["value"] == indicator["description"]
    assert indicator["data_date"] == "2026-08-12"
    assert indicator["confidence"] == "high"


def test_region_demand_signal_joins_profile_and_qualifying_good_traffic(tmp_path, monkeypatch):
    from app.core import db
    from fastapi.testclient import TestClient
    from app.main import app

    seed_path = tmp_path / "region.seed.json"
    seed_path.write_text(json.dumps([{
        "country_code": "US",
        "country_name": "United States",
        "economic_indicators": [{"label": "Demand fit", "value": "Strong", "source": "World Bank", "data_date": "2026-08-12", "confidence": "high"}],
        "cultural_context": [{"label": "Business context", "value": "English-speaking", "source": "Trade source", "data_date": "2026-08-12", "confidence": "medium"}],
        "conflict_indicators": [{"label": "Conflict", "value": "No active civil war", "source": "UCDP", "data_date": "2026-08-12", "confidence": "high"}],
        "sources": [{"name": "World Bank", "type": "economic"}],
        "updated_at": "2026-08-12T00:00:00+00:00",
    }]))
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "hub.db")
    monkeypatch.setattr(db, "REGION_SEED_PATH", seed_path)
    conn = db.connect()
    conn.execute("""
        INSERT INTO ip_profiles
          (ip,country,country_code,organization,organization_confidence,is_hosting,is_vpn,is_proxy,is_tor,fetched_at)
        VALUES (?,?,?,?,?,?,?,?,?,?)
    """, ("8.8.8.8", "United States", "US", "Example ISP", 85, 0, None, None, 0, "2026-08-12T00:00:00+00:00"))
    conn.execute("""
        INSERT INTO ip_observations
          (ip,requests,status_4xx,status_5xx,unique_paths,wp_login_requests,sensitive_probe_requests,bot_requests,behavior_score,updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?)
    """, ("8.8.8.8", 100, 0, 0, 2, 0, 0, 0, 0, "2026-08-12T00:00:00+00:00"))
    conn.commit(); conn.close()

    response = TestClient(app).get("/api/regions/demand-signal?limit=5")
    assert response.status_code == 200
    item = next(row for row in response.json() if row["country_code"] == "US")
    assert item["good_ip_count"] == 1
    assert item["good_requests"] == 100
    assert item["product_demand"] is None
    assert item["conflict_indicators"][0]["type"] == "none"


def test_region_list_endpoint_returns_seeded_profiles():
    from fastapi.testclient import TestClient
    from app.main import app

    client = TestClient(app)
    res = client.get("/api/regions?limit=5")
    assert res.status_code == 200
    data = res.json()
    assert data
    assert "country_code" in data[0]
    assert {"market_score", "market_level", "market_evidence"} <= data[0].keys()


def test_region_detail_endpoint_and_pages_handle_known_and_unknown_regions():
    from fastapi.testclient import TestClient
    from app.main import app

    client = TestClient(app)
    known = client.get("/api/regions/US")
    unknown = client.get("/api/regions/ZZ")
    region_list_page = client.get("/regions")
    unknown_page = client.get("/regions/ZZ")
    assert known.status_code == 200
    assert {"market_score", "market_level", "market_evidence"} <= known.json().keys()
    assert unknown.status_code == 404
    assert region_list_page.status_code == 200
    assert "Region profiles" in region_list_page.text
    assert unknown_page.status_code == 200
    assert "Region profile unavailable" in unknown_page.text


def test_list_and_detail_endpoints_share_canonical_threat_score(tmp_path, monkeypatch):
    from app.core import db
    from fastapi.testclient import TestClient
    from app.main import app

    monkeypatch.setattr(db, "DB_PATH", tmp_path / "hub.db")
    monkeypatch.setattr(db, "REGION_SEED_PATH", tmp_path / "missing.seed.json")
    conn = db.connect()
    conn.execute(
        """INSERT INTO ip_profiles
           (ip,country,country_code,organization,organization_confidence,is_hosting,is_tor,
            core_enrichment_status,next_retry_at,fetched_at)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        ("8.8.8.8", "United States", "US", "Example ISP", 85, 0, 0, "complete", None, "2026-08-12T00:00:00+00:00"),
    )
    conn.execute(
        """INSERT INTO ip_observations
           (ip,requests,status_4xx,status_5xx,unique_paths,wp_login_requests,
            sensitive_probe_requests,bot_requests,behavior_score,updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        ("8.8.8.8", 10, 3, 0, 2, 0, 0, 0, 30, "2026-08-12T00:00:00+00:00"),
    )
    conn.commit()
    conn.close()

    client = TestClient(app)
    listed = next(item for item in client.get("/api/ips?limit=10").json() if item["ip"] == "8.8.8.8")
    detailed = client.get("/api/ip/8.8.8.8").json()
    assert listed["threat_signal_score"] == detailed["threat_signal_score"]
    assert listed["threat_signal_score"] == listed["classification"]["score"]
    assert detailed["threat_signal_score"] == detailed["classification"]["score"]


def test_calibration_endpoint_returns_csv():
    from fastapi.testclient import TestClient
    from app.main import app

    response = TestClient(app).get("/api/ips/calibration.csv")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert response.text.splitlines()[0].startswith("ip,predicted_label")


def test_ip_case_page_is_a_full_page_route():
    from fastapi.testclient import TestClient
    from app.main import app

    response = TestClient(app).get("/ip/8.8.8.8")
    assert response.status_code == 200
    assert "Investigation case" in response.text
    assert "/api/ip/" in response.text


def test_frontend_uses_only_canonical_threat_signal_score():
    from fastapi.testclient import TestClient
    from app.main import app

    client = TestClient(app)
    dashboard = client.get("/").text
    detail = client.get("/ip/8.8.8.8").text
    assert "const signalScore=x=>Number(x.threat_signal_score??0)" in dashboard
    assert "effective_risk_score" not in dashboard
    assert "Number(d.threat_signal_score??0)" in detail
    assert "Number(c.score||0)" not in detail


def test_region_detail_inherits_shared_theme_without_own_toggle():
    from fastapi.testclient import TestClient
    from app.main import app

    page = TestClient(app).get("/regions/AU")
    assert page.status_code == 200
    assert "localStorage.getItem('sentinel-theme') || 'dark'" in page.text
    assert "window.addEventListener('storage'" in page.text
    assert "id=\"theme-toggle\"" not in page.text
