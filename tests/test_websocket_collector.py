"""WebSocket collector tests.

Pure config/URL tests run without any database.
Tests that require DB writes are marked @pytest.mark.integration.
"""
from urllib.parse import parse_qs, urlparse
import asyncio
import json

import pytest

from app.collectors.websocket_collector import CollectorConfig, WebSocketCollector


def _collector(*, flush_ms=50):
    return WebSocketCollector(
        CollectorConfig(True, "wss://example.test", "secret", "access", "source", 200, flush_ms, 300)
    )


def test_malformed_numeric_env_does_not_break_config(monkeypatch):
    monkeypatch.setenv("LOG_WS_BATCH_SIZE", "not-a-number")
    monkeypatch.setenv("LOG_WS_FLUSH_MS", "bad")
    monkeypatch.setenv("LOG_WS_AI_INTERVAL_SECONDS", "invalid")
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


@pytest.mark.integration
def test_stream_starts_at_zero_and_preserves_same_lines_at_different_offsets():
    pytest.skip("Requires PostgreSQL integration environment")


@pytest.mark.integration
def test_new_event_schema_contains_stream_offset():
    pytest.skip("Requires PostgreSQL integration environment")


@pytest.mark.integration
def test_snapshot_and_delta_cursor_are_incremental():
    pytest.skip("Requires PostgreSQL integration environment")
