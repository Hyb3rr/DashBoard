from datetime import datetime, timedelta, timezone
import asyncio
import json

from app.core import db
from app.core.buckets import bucket_sums, upsert_buckets
from app.core.logs import rebuild_observations
from app.core.correlation import asn_clusters
from app.services.dispositions import ensure_disposition, set_disposition


def test_bucket_upsert_is_idempotent_and_exposes_burst(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "hub.db")
    monkeypatch.setattr(db, "REGION_SEED_PATH", tmp_path / "missing.seed.json")
    conn = db.connect()
    start = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    events = [
        {"src_ip": "203.0.113.8", "timestamp": (start + timedelta(seconds=i % 60)).isoformat(),
         "path": f"/scan/{i}", "status": 404, "bytes_sent": 1,
         "user_agent": "curl"}
        for i in range(300)
    ]
    upsert_buckets(conn, events)
    upsert_buckets(conn, events[:3])
    sums = bucket_sums(conn, "203.0.113.8", start - timedelta(minutes=1), start + timedelta(minutes=2))
    assert sums["203.0.113.8"]["requests"] == 303
    assert sums["203.0.113.8"]["peak_requests_1m"] == 303
    assert sums["203.0.113.8"]["peak_requests_5m"] == 303
    conn.close()


def test_observation_score_matches_persisted_detection_points(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "hub.db")
    monkeypatch.setattr(db, "REGION_SEED_PATH", tmp_path / "missing.seed.json")
    conn = db.connect()
    stamp = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    upsert_buckets(conn, [
        {"src_ip": "198.51.100.9", "timestamp": stamp.isoformat(), "path": "/.env",
         "status": 404, "bytes_sent": 1, "user_agent": "curl"},
    ])
    rebuild_observations(conn)
    row = conn.execute("SELECT behavior_score, detections_json FROM ip_observations WHERE ip=?", ("198.51.100.9",)).fetchone()
    import json
    detections = json.loads(row["detections_json"])
    assert row["behavior_score"] == min(sum(item["points"] for item in detections), 100)
    assert row["behavior_score"] == 50
    conn.close()


def test_windowed_detections_do_not_leak_old_burst_into_one_hour(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "hub.db")
    monkeypatch.setattr(db, "REGION_SEED_PATH", tmp_path / "missing.seed.json")
    conn = db.connect()
    old = (datetime.now(timezone.utc) - timedelta(hours=23)).replace(second=0, microsecond=0)
    upsert_buckets(conn, [
        {"src_ip": "198.51.100.20", "timestamp": old.isoformat(), "path": f"/scan/{i}", "status": 404, "user_agent": "curl"}
        for i in range(100)
    ])
    rebuild_observations(conn)
    row = conn.execute("SELECT detections_1h_json,detections_24h_json FROM ip_observations WHERE ip=?", ("198.51.100.20",)).fetchone()
    one_hour = {item["id"] for item in json.loads(row["detections_1h_json"])}
    day = {item["id"] for item in json.loads(row["detections_24h_json"])}
    assert "WEB-BURST-001" not in one_hour
    assert "WEB-BURST-001" not in day
    assert "WEB-SCAN-001" in day
    conn.close()


def test_privacy_provider_freshness_and_proxy_type(monkeypatch):
    from app.core import enrichment

    monkeypatch.setattr(enrichment, "_maxmind", lambda ip: ({"country": "Test", "country_code": "TS", "latitude": 1.0, "longitude": 2.0}, [], "active"))
    monkeypatch.setattr(enrichment, "_anonymous_ip", lambda ip: ({"is_vpn": False, "is_proxy": True, "proxy_type": "residential", "is_tor": False, "is_hosting": False}, [], "active"))
    monkeypatch.setattr(enrichment, "_tor_exit_list", lambda ip: ({"is_tor": False}, [], "active"))
    monkeypatch.setenv("STALE_HOURS", "72")

    result = asyncio.run(enrichment.lookup("8.8.8.8", refresh=True))
    assert result["proxy_type"] == "residential"
    assert result["provider_status"]["MaxMind City/ASN"]["checked_at"]
    due = datetime.fromisoformat(result["privacy_recheck_due_at"])
    fetched = datetime.fromisoformat(result["fetched_at"])
    assert timedelta(hours=71, minutes=59) <= due - fetched <= timedelta(hours=72, seconds=1)


def test_asn_cluster_requires_shared_sensitive_paths_and_excludes_other_asn(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "hub.db")
    monkeypatch.setattr(db, "REGION_SEED_PATH", tmp_path / "missing.seed.json")
    conn = db.connect()
    stamp = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    for index in range(1, 7):
        ip = f"198.51.100.{index}"
        asn = "AS64500" if index < 6 else "AS64501"
        conn.execute("INSERT INTO ip_profiles(ip, asn, organization, fetched_at) VALUES (?, ?, ?, ?)", (ip, asn, "Example Net", stamp.isoformat()))
        upsert_buckets(conn, [
            {"src_ip": ip, "timestamp": (stamp + timedelta(minutes=index % 3)).isoformat(), "path": path, "status": 404}
            for path in ("/.env", "/.git/config", "/wp-config.php")
        ])
    clusters = asn_clusters(conn, stamp - timedelta(minutes=1))
    assert len(clusters) == 1
    assert len(clusters[0]["member_ips"]) == 5
    assert clusters[0]["shared_paths"] == ["/.env", "/.git/config", "/wp-config.php"]
    conn.close()


def test_disposition_history_survives_recommendation_refresh(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "hub.db")
    monkeypatch.setattr(db, "REGION_SEED_PATH", tmp_path / "missing.seed.json")
    conn = db.connect()
    initial = ensure_disposition(conn, "203.0.113.44", "bad")
    assert initial["state"] == "new"
    assert initial["suggested_state"] == "investigate"
    set_disposition(conn, "203.0.113.44", "resolved", note="closed", actor="analyst", label="bad")
    refreshed = ensure_disposition(conn, "203.0.113.44", "watch")
    assert refreshed["state"] == "resolved"
    assert refreshed["suggested_state"] == "monitor"
    assert refreshed["history"][0]["to"] == "resolved"
    conn.close()
