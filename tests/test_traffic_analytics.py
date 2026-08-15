from datetime import datetime, timedelta, timezone

from app.core import db


def test_traffic_range_uses_fixed_time_buckets(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "hub.db")
    monkeypatch.setattr(db, "REGION_SEED_PATH", tmp_path / "missing.seed.json")
    conn = db.connect()
    # Keep the oldest sample safely inside the one-hour window even though
    # the endpoint evaluates its current-time boundary a few milliseconds
    # after this fixture creates the rows.
    end = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    for index in range(6):
        stamp = (end - timedelta(minutes=index * 10)).isoformat()
        conn.execute(
            """INSERT INTO events
               (source,line_hash,raw_line,timestamp,src_ip,method,path,status,bytes_sent,imported_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            ("ws:test", f"hash-{index}", "raw", stamp, f"8.8.8.{index + 1}", "GET", "/", 200, 10, stamp),
        )
    conn.commit()
    conn.close()

    from app.main import traffic_analytics

    one_hour = traffic_analytics("1h")
    half_hour = traffic_analytics("30m")
    assert one_hour["bucket"] == "10min"
    assert len(one_hour["series"]) >= 6
    assert half_hour["bucket"] == "5min"
    assert len(half_hour["series"]) >= 6
    assert sum(item["requests"] for item in one_hour["series"]) == 6
    assert any(item["requests"] == 0 for item in one_hour["series"])


def test_traffic_custom_window_filters_and_zero_fills(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "hub.db")
    monkeypatch.setattr(db, "REGION_SEED_PATH", tmp_path / "missing.seed.json")
    conn = db.connect()
    start = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    for index, (minutes, status) in enumerate(((5, 200), (25, 404), (55, 500))):
        stamp = start + timedelta(minutes=minutes)
        conn.execute(
            """INSERT INTO events
               (source,line_hash,raw_line,timestamp,src_ip,method,path,status,bytes_sent,imported_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            ("ws:test", f"custom-{index}", "raw", stamp.isoformat(), "9.9.9.9", "GET", "/", status, 10, stamp.isoformat()),
        )
    conn.commit()
    conn.close()

    from app.main import traffic_analytics

    data = traffic_analytics("1h", start=start.isoformat(), end=(start + timedelta(hours=1)).isoformat())
    assert data["range"] == "custom"
    assert data["total_requests"] == 3
    assert data["status_codes"] == {"2xx": 1, "3xx": 0, "4xx": 1, "5xx": 1}
    assert data["series"][-1]["requests"] == 0


def test_traffic_empty_window_returns_flat_zero_series(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "hub.db")
    monkeypatch.setattr(db, "REGION_SEED_PATH", tmp_path / "missing.seed.json")
    from app.main import traffic_analytics

    data = traffic_analytics("1h")
    assert data["series"]
    assert sum(item["requests"] for item in data["series"]) == 0
    assert all(item["requests"] == 0 for item in data["series"])


def test_ip_traffic_reaches_window_end_with_zero_bucket(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "hub.db")
    monkeypatch.setattr(db, "REGION_SEED_PATH", tmp_path / "missing.seed.json")
    start = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    conn = db.connect()
    stamp = start + timedelta(minutes=5)
    conn.execute(
        """INSERT INTO events
           (source,line_hash,raw_line,timestamp,src_ip,method,path,status,bytes_sent,imported_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        ("ws:test", "ip-traffic-1", "raw", stamp.isoformat(), "7.7.7.7", "GET", "/", 404, 10, stamp.isoformat()),
    )
    conn.commit()
    conn.close()

    from app.main import ip_traffic

    data = ip_traffic("7.7.7.7", "1h", start=start.isoformat(), end=(start + timedelta(hours=1)).isoformat())
    assert data["total_requests"] == 1
    assert data["status_codes"]["4xx"] == 1
    assert data["series"][-1]["requests"] == 0


def test_traffic_filter_and_exclude_reaggregate_same_window(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "hub.db")
    monkeypatch.setattr(db, "REGION_SEED_PATH", tmp_path / "missing.seed.json")
    start = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    conn = db.connect()
    for index, ip, path in ((1, "1.1.1.1", "/"), (2, "2.2.2.2", "/login"), (3, "1.1.1.1", "/")):
        stamp = start + timedelta(minutes=index)
        conn.execute(
            """INSERT INTO events
               (source,line_hash,raw_line,timestamp,src_ip,method,path,status,bytes_sent,imported_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            ("ws:test", f"filter-{index}", "raw", stamp.isoformat(), ip, "GET", path, 200, 10, stamp.isoformat()),
        )
    conn.commit()
    conn.close()

    from app.main import traffic_analytics

    kwargs = {"start": start.isoformat(), "end": (start + timedelta(hours=1)).isoformat()}
    filtered = traffic_analytics("1h", filter_type="ip", filter_value="1.1.1.1", **kwargs)
    excluded = traffic_analytics("1h", filter_type="ip", filter_value="1.1.1.1", exclude=True, **kwargs)
    assert filtered["total_requests"] == 2
    assert filtered["top_paths"][0]["path"] == "/"
    assert excluded["total_requests"] == 1
    assert excluded["top_ips"][0]["ip"] == "2.2.2.2"
