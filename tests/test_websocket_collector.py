import json
from urllib.parse import parse_qs, urlparse
import pytest

from app.core import db
from app.collectors.websocket_collector import CollectorConfig, WebSocketCollector


@pytest.fixture
def isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "hub.db")
    monkeypatch.setattr(db, "REGION_SEED_PATH", tmp_path / "missing.seed.json")
    return tmp_path


@pytest.mark.asyncio
async def test_stream_starts_at_zero_and_preserves_same_lines_at_different_offsets(
    isolated_db,
):
    collector = WebSocketCollector(
        CollectorConfig(
            False, "wss://example.test/ws", "secret", "access", "test", 200, 500, 300
        )
    )
    line = '8.8.8.8 - - [14/Aug/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 12 "-" "ua"'
    length = len(line.encode()) + 1

    await collector.handle_message(json.dumps({"type": "lines", "items": [line]}), 0)
    assert (
        await collector.handle_message(
            json.dumps({"type": "offset", "value": length}), 0
        )
        == length
    )
    await collector.handle_message(
        json.dumps({"type": "lines", "items": [line]}), length
    )
    assert (
        await collector.handle_message(
            json.dumps({"type": "offset", "value": length * 2}), length
        )
        == length * 2
    )

    conn = db.connect()
    try:
        assert [
            row["source_offset"]
            for row in conn.execute("SELECT source_offset FROM events ORDER BY id")
        ] == [0, length]
        assert (
            conn.execute(
                "SELECT requests FROM ip_observations WHERE ip = '8.8.8.8'"
            ).fetchone()["requests"]
            == 2
        )
        assert (
            conn.execute(
                "SELECT last_offset FROM log_sources WHERE source_id = 'test'"
            ).fetchone()["last_offset"]
            == length * 2
        )
    finally:
        conn.close()


def test_malformed_numeric_env_does_not_break_config(monkeypatch):
    monkeypatch.setenv("LOG_WS_BATCH_SIZE", "not-a-number")
    monkeypatch.setenv("LOG_WS_FLUSH_MS", "bad")
    monkeypatch.setenv("LOG_WS_AI_INTERVAL_SECONDS", "invalid")
    config = CollectorConfig.from_env()
    assert config.batch_size == 200
    assert config.flush_ms == 500
    assert config.ai_interval_seconds == 300


def test_connection_url_includes_identity_and_persisted_offset():
    collector = WebSocketCollector(
        CollectorConfig(
            True,
            "wss://example.test/log-ws?tenant=demo",
            "secret",
            "access",
            "azure-access",
            200,
            500,
            300,
        )
    )

    query = parse_qs(urlparse(collector._connection_url(44551725)).query)

    assert query["offset"] == ["44551725"]
    assert query["source_id"] == ["azure-access"]
    assert query["client"] == ["azure-access"]
    assert query["clientId"] == ["azure-access"]


def test_new_event_schema_contains_stream_offset(isolated_db):
    conn = db.connect()
    try:
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(events)")}
        assert "source_offset" in columns
        assert conn.execute(
            "SELECT name FROM sqlite_master WHERE name = 'log_sources'"
        ).fetchone()
        assert conn.execute(
            "SELECT name FROM sqlite_master WHERE name = 'ip_change_log'"
        ).fetchone()
    finally:
        conn.close()


def test_snapshot_and_delta_cursor_are_incremental(isolated_db):
    from fastapi.testclient import TestClient
    from app.main import app

    conn = db.connect()
    for ip in ("8.8.8.8", "1.1.1.1"):
        conn.execute(
            "INSERT INTO ip_observations (ip, requests, updated_at) VALUES (?, 1, '2026-08-14T00:00:00+00:00')",
            (ip,),
        )
        conn.execute(
            "INSERT INTO ip_change_log (ip, reason, changed_at) VALUES (?, 'traffic', '2026-08-14T00:00:00+00:00')",
            (ip,),
        )
    conn.commit()
    conn.close()

    with TestClient(app) as client:
        snapshot = client.get("/api/ips/snapshot?limit=500").json()
        assert snapshot["cursor"] == 2
        assert {item["ip"] for item in snapshot["items"]} == {"8.8.8.8", "1.1.1.1"}
        first = client.get("/api/ips/updates?after=0&limit=1").json()
        assert first["has_more"] is True
        assert first["cursor"] == 1
        second = client.get(f"/api/ips/updates?after={first['cursor']}&limit=1").json()
        assert second["has_more"] is False
        assert second["cursor"] == 2
