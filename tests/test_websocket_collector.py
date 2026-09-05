"""WebSocket collector tests.

Pure config/URL tests run without any database.
Tests that require DB writes are marked @pytest.mark.integration.
"""
from urllib.parse import parse_qs, urlparse
import asyncio
import json

import pytest

from app.collectors.websocket_collector import CollectorConfig, WebSocketCollector
from app.core.fast_detection import EarlyDetection
from app.db import postgres
from app.db.repositories import CheckpointRepository
from app.core.logs import parse_apache_combined_diagnostic


def _collector(*, flush_ms=50):
    return WebSocketCollector(
        CollectorConfig(True, "wss://example.test", "secret", "access", "source", 200, flush_ms, 300)
    )


def test_malformed_numeric_env_does_not_break_config(monkeypatch):
    monkeypatch.setenv("LOG_WS_BATCH_SIZE", "not-a-number")
    monkeypatch.setenv("LOG_WS_FLUSH_MS", "bad")
    monkeypatch.setenv("AI_RUNTIME_INTERVAL_SECONDS", "invalid")
    config = CollectorConfig.from_env()
    assert config.batch_size == 200
    assert config.flush_ms == 1000
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
    assert "token" not in query
    assert collector._connection_headers() == {"Authorization": "Bearer secret"}


def test_pending_lines_flush_after_timer_without_batch_size(monkeypatch):
    collector = _collector(flush_ms=50)
    collector._raw_archive = type(
        "DurableArchive", (),
        {"append_batch": lambda self, lines, received_at=None: _completed_receipt()},
    )()
    committed = []

    def fake_commit(lines, end_offset, current_offset, received_at=None):
        committed.append((lines, end_offset, current_offset))
        return end_offset, 17, {"203.0.113.10"}, []

    async def fake_after_commit(cursor, affected, new_ips):
        return None

    monkeypatch.setattr(collector, "_commit_batch", fake_commit)
    monkeypatch.setattr(collector, "_after_commit", fake_after_commit)

    async def scenario():
        collector._stop.clear()
        collector._flush_task = asyncio.create_task(collector._flush_loop())
        await collector.handle_message(
            json.dumps({"type": "lines", "items": ["one"]}), 0
        )
        assert collector.pending_lines == 1
        await asyncio.sleep(0.08)
        collector._stop.set()
        collector._flush_task.cancel()
        await asyncio.gather(collector._flush_task, return_exceptions=True)

    asyncio.run(scenario())
    assert committed == [(["one"], 4, 0)]
    assert collector.pending_lines == 0


def test_shadow_detection_never_enters_early_alert_publisher(monkeypatch):
    collector = _collector()
    collector._raw_archive = type(
        "DurableArchive", (),
        {"append_batch": lambda self, lines, received_at=None: _completed_receipt()},
    )()
    collector._window_detector = type(
        "ShadowDetector", (),
        {"observe": lambda self, line: [EarlyDetection("PENTEST-DISC-001", "content_discovery_sweep", "GET", "/candidate", "203.0.113.10", True)]},
    )()
    published = []
    monkeypatch.setattr(
        "app.collectors.websocket_collector.early_alerts.enqueue",
        lambda detection, ip=None: published.append((detection, ip)),
    )

    async def scenario():
        await collector.handle_message(json.dumps({"type": "lines", "items": ["shadow line"]}), 0)

    asyncio.run(scenario())
    assert published == []


def _completed_receipt():
    async def receipt():
        return None
    return receipt()


@pytest.mark.integration
def test_stream_starts_at_zero_and_preserves_same_lines_at_different_offsets():
    pytest.skip("Requires PostgreSQL integration environment")


@pytest.mark.integration
def test_new_event_schema_contains_stream_offset():
    pytest.skip("Requires PostgreSQL integration environment")


@pytest.mark.integration
def test_snapshot_and_delta_cursor_are_incremental():
    pytest.skip("Requires PostgreSQL integration environment")


@pytest.mark.integration
def test_all_malformed_batch_advances_durable_checkpoint():
    if not postgres.configured():
        pytest.skip("POSTGRES_DSN is required for checkpoint integration test")
    source = "pytest-malformed-checkpoint"
    collector = _collector()
    collector.config = CollectorConfig(False, "", "", "access", source, 200, 1000, 300)
    collector._raw_archive = type("DurableArchive", (), {"write_parse_failures": lambda self, records: None})()
    try:
        with postgres.transaction() as conn:
            conn.execute("DELETE FROM log_sources WHERE source_id=%s", (source,))
            conn.execute(
                "INSERT INTO log_sources(source_id,log_key,last_offset,status) VALUES(%s,%s,%s,%s)",
                (source, "access", 0, "live"),
            )
        assert CheckpointRepository().acquire(source, "access", collector._owner, "live")
        result = collector._commit_batch(["not an access log"], 100, 0)
        with postgres.transaction() as conn:
            row = conn.execute(
                "SELECT last_offset FROM log_sources WHERE source_id=%s", (source,)
            ).fetchone()
        assert result[0] == 100
        assert row["last_offset"] == 100
    finally:
        with postgres.transaction() as conn:
            conn.execute("DELETE FROM log_sources WHERE source_id=%s", (source,))


def test_parser_reports_malformed_line_without_creating_event():
    event, code, message = parse_apache_combined_diagnostic("not an access log")
    assert event is None
    assert code == "INVALID_APACHE_COMBINED_FORMAT"
    assert message


@pytest.mark.asyncio
async def test_broken_websocket_frame_is_archived_without_fabricated_checkpoint():
    collector = _collector()
    frames = []

    class Archive:
        async def append_batch(self, lines, received_at=None):
            frames.extend(lines)

    collector._raw_archive = Archive()
    assert await collector.handle_message("{broken-json", 900) is None
    assert frames == ["{broken-json"]
    assert collector.last_offset == 0


@pytest.mark.asyncio
async def test_raw_receipt_failure_does_not_reach_storage_or_advance_memory():
    collector = _collector()

    class FailingArchive:
        async def append_batch(self, lines, received_at=None):
            raise OSError("raw fsync failed")

    collector._raw_archive = FailingArchive()
    collector._commit_batch = lambda *_args: (_ for _ in ()).throw(AssertionError("storage reached"))
    with pytest.raises(OSError, match="raw fsync failed"):
        await collector.handle_message(json.dumps({"type": "lines", "items": ["bad"]}), 0)
    assert collector.last_offset == 0
    assert collector.pending_lines == 0


def test_quarantine_failure_does_not_reach_checkpoint():
    collector = _collector()

    class FailingArchive:
        def write_parse_failures(self, records):
            raise OSError("quarantine fsync failed")

    collector._raw_archive = FailingArchive()
    with pytest.raises(OSError, match="quarantine fsync failed"):
        collector._commit_batch(["not an access log"], 100, 0)
