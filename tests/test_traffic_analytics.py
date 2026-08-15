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
    assert len(one_hour["series"]) == 6
    assert half_hour["bucket"] == "5min"
    assert len(half_hour["series"]) == 6
    assert sum(item["requests"] for item in one_hour["series"]) == 6
