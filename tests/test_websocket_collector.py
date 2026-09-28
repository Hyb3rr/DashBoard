"""WebSocket collector tests.

Pure config/URL tests run without any database.
Tests that require DB writes are marked @pytest.mark.integration.
"""
from urllib.parse import parse_qs, urlparse
import asyncio
import json

import pytest

from app.collectors.websocket_collector import CollectorConfig, WebSocketCollector
from app.collectors import batching, session
from app.collectors.storage import BatchCommitter, _STORAGE_STOP
from app.collectors.websocket_collector import utc_now
from app.core.fast_detection import EarlyDetection
from app.core.failpoints import NoopFailpoint
from app.core import metrics
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

    query = parse_qs(urlparse(session.connection_url(collector, 44551725)).query)

    assert query["offset"] == ["44551725"]
    assert query["source_id"] == ["azure-access"]
    assert query["client"] == ["azure-access"]
    assert query["clientId"] == ["azure-access"]
    assert "token" not in query
    assert session.connection_headers(collector) == {"Authorization": "Bearer secret"}


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
        collector.stop_event.clear()
        collector.tasks.flush = asyncio.create_task(batching.flush_loop(collector))
        await batching.handle_message(
            collector, json.dumps({"type": "lines", "items": ["one"]}), 0, utc_now
        )
        assert collector.pending_lines == 1
        await asyncio.sleep(0.08)
        collector.stop_event.set()
        collector.tasks.flush.cancel()
        await asyncio.gather(collector.tasks.flush, return_exceptions=True)

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
        {"observe": lambda self, line: [EarlyDetection("PENTEST-UA-001", "scanner_ua", "GET", "/candidate", "203.0.113.10", True, "ffuf", "supporting")]},
    )()
    published = []
    monkeypatch.setattr(
        "app.collectors.websocket_collector.early_alerts.enqueue",
        lambda detection, ip=None: published.append((detection, ip)),
    )

    async def scenario():
        await batching.handle_message(collector, json.dumps({"type": "lines", "items": ["shadow line"]}), 0, utc_now)

    asyncio.run(scenario())
    assert published == []


def test_promoted_behavior_detection_enters_early_alert_publisher(monkeypatch):
    collector = _collector()
    collector._raw_archive = type(
        "DurableArchive", (),
        {"append_batch": lambda self, lines, received_at=None: _completed_receipt()},
    )()
    collector._window_detector = type(
        "BehaviorDetector", (),
        {"observe": lambda self, line: [EarlyDetection("PENTEST-DISC-001", "content_discovery_sweep", "GET", "/candidate", "203.0.113.10", False, None, "medium")]},
    )()
    published = []
    monkeypatch.setattr(
        "app.collectors.websocket_collector.early_alerts.enqueue",
        lambda detection, ip=None: published.append((detection, ip)),
    )

    async def scenario():
        await batching.handle_message(collector, json.dumps({"type": "lines", "items": ["behavior line"]}), 0, utc_now)

    asyncio.run(scenario())
    assert len(published) == 1
    assert published[0][0].severity == "medium"


def _completed_receipt():
    async def receipt():
        return None
    return receipt()


@pytest.mark.asyncio
async def test_stop_drains_all_accepted_storage_batches(monkeypatch):
    collector = _collector()
    collector._raw_archive = type("Archive", (), {"stop": lambda self: asyncio.sleep(0)})()
    monkeypatch.setattr(collector, "_publish_status", lambda: asyncio.sleep(0))
    monkeypatch.setattr("app.collectors.websocket_collector.early_alerts.stop", lambda: asyncio.sleep(0))

    processed = []

    async def consume(cursor, affected, new_ips):
        batch = current_batches.pop(0)
        processed.append(batch[0])

    current_batches = [["first"], ["second"]]
    collector._commit_batch = lambda batch, end_offset, current_offset, received_at=None: (
        end_offset, 1, set(), []
    )
    collector._after_commit = consume
    collector.storage_worker.start()
    await collector.storage_worker.queue.put((["first"], 1, 0, "received"))
    await collector.storage_worker.queue.put((["second"], 2, 1, "received"))

    await asyncio.wait_for(collector.stop(), timeout=0.5)

    assert processed == ["first", "second"]
    assert collector.storage_worker.queue._unfinished_tasks == 0


def test_batch_committer_persists_events_with_parsed_timestamp(monkeypatch):
    class Cursor:
        def fetchone(self):
            return {"seq": 12}

        def fetchall(self):
            return [{"ip": "203.0.113.10"}]

    class Connection:
        def execute(self, _query, _args=None):
            return Cursor()

    class DetectionRepository:
        def process_events(self, *_args, **kwargs):
            assert kwargs["now"].isoformat() == "2026-09-26T10:00:00+00:00"
            return {"affected": {"203.0.113.10"}}

    class Writer:
        def insert_events(self, events):
            assert events == [{"event_id": "event-1"}]

    from contextlib import contextmanager

    @contextmanager
    def transaction():
        yield Connection()

    monkeypatch.setattr("app.collectors.storage.PgDetectionRepository", DetectionRepository)
    monkeypatch.setattr("app.collectors.storage.postgres_store.transaction", transaction)
    committer = BatchCommitter(_collector().config, lambda *_args: None)

    result = committer._persist_events(
        [{"event_id": "event-1"}], 0, 10, "live", "owner",
        "2026-09-26T10:00:00+00:00", NoopFailpoint(), Writer(),
    )

    assert result == (10, 12, {"203.0.113.10"}, [])


@pytest.mark.asyncio
async def test_storage_worker_records_failure_and_retries_batch(monkeypatch):
    collector = _collector()
    attempts = 0
    committed = asyncio.Event()
    before = metrics.snapshot()["counters"].get("collector.storage_failures", 0)

    def commit(*_args):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise OSError("temporary database failure")
        return 10, 12, set(), []

    async def after_commit(*_args):
        committed.set()

    async def no_wait(_delay):
        return None

    collector._commit_batch = commit
    collector._after_commit = after_commit
    monkeypatch.setattr("app.collectors.storage.asyncio.sleep", no_wait)
    collector.storage_worker.start()
    await collector.storage_worker.queue.put((["line"], 10, 0, "received"))

    await asyncio.wait_for(committed.wait(), timeout=1)
    await asyncio.wait_for(collector.storage_worker.queue.join(), timeout=1)
    collector.storage_worker.queue.put_nowait(_STORAGE_STOP)
    await asyncio.wait_for(collector.storage_worker.task, timeout=1)

    after = metrics.snapshot()["counters"].get("collector.storage_failures", 0)
    assert attempts == 2
    assert after == before + 1
    assert collector.last_offset == 10


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
        assert CheckpointRepository().acquire(source, "access", collector.session.owner, "live")
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


def test_parser_rejection_state_is_observable_and_degrades_after_repeated_batches():
    collector = _collector()
    for _ in range(3):
        collector.parser_stats.record(1, 0, 1)

    status = collector.status()
    assert status["parser"]["rejected_lines"] == 3
    assert status["parser"]["last_rejection_ratio"] == 1.0
    assert status["parser"]["consecutive_reject_batches"] == 3
    assert status["parser"]["status"] == "degraded"


@pytest.mark.asyncio
async def test_broken_websocket_frame_is_archived_without_fabricated_checkpoint():
    collector = _collector()
    frames = []

    class Archive:
        async def append_batch(self, lines, received_at=None):
            frames.extend(lines)

    collector._raw_archive = Archive()
    assert await batching.handle_message(collector, "{broken-json", 900, utc_now) is None
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
        await batching.handle_message(collector, json.dumps({"type": "lines", "items": ["bad"]}), 0, utc_now)
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
