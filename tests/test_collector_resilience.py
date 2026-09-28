import asyncio

import pytest

from app.collectors.websocket_collector import CollectorConfig, WebSocketCollector
from app.collectors import batching, session
from app.collectors.websocket_collector import utc_now


def _config() -> CollectorConfig:
    return CollectorConfig(
        enabled=True,
        url="wss://example.test/logs",
        token="token",
        log_key="access",
        source_id="source",
        batch_size=10,
        flush_ms=1000,
    )


@pytest.mark.asyncio
async def test_supervisor_restarts_run_after_unexpected_failure(monkeypatch):
    collector = WebSocketCollector(_config())
    calls = 0

    async def flaky_run():
        nonlocal calls
        calls += 1
        if calls == 1:
            raise ConnectionError("postgres unavailable")
        collector.stop_event.set()

    async def no_status():
        return None

    monkeypatch.setattr(collector.session, "run", lambda *_args: flaky_run())
    monkeypatch.setattr(collector, "_publish_status", no_status)
    collector.stop_event.clear()
    collector.session.supervisor_backoff = 0

    await asyncio.wait_for(collector.session.supervise(utc_now), timeout=1)

    assert calls == 2
    assert collector.state == "retrying"


@pytest.mark.asyncio
async def test_status_persistence_failure_does_not_escape(monkeypatch):
    collector = WebSocketCollector(_config())

    def fail_status():
        raise ConnectionError("postgres unavailable")

    monkeypatch.setattr(collector, "_persist_status", fail_status)

    await collector._publish_status()

    assert collector.last_error == "ConnectionError: postgres unavailable"


def test_api_status_uses_persisted_control_plane_when_local_collector_is_not_running(monkeypatch):
    collector = WebSocketCollector(_config())
    monkeypatch.setattr(collector, "status", lambda: {
        "enabled": True, "status": "not_started", "tasks": {"run": "not_started"},
    })
    monkeypatch.setattr(
        "app.collectors.websocket_collector.CheckpointRepository.read_status",
        lambda _repo, _source: {
            "source_id": "source", "log_key": "access", "status": "live",
            "last_offset": 123, "last_error": None, "last_event_at": None,
            "lease_owner": "collector-1", "lease_expires_at": None,
            "updated_at": None,
        },
    )

    result = collector.shared_status()

    assert result["status"] == "live"
    assert result["last_offset"] == 123
    assert result["shared_control_plane"] is True
    assert result["lease_owner_present"] is True


def test_api_status_marks_expired_shared_lease_stale(monkeypatch):
    from datetime import datetime, timedelta, timezone

    collector = WebSocketCollector(_config())
    monkeypatch.setattr(collector, "status", lambda: {
        "enabled": True, "status": "not_started", "tasks": {"run": "not_started"},
    })
    monkeypatch.setattr(
        "app.collectors.websocket_collector.CheckpointRepository.read_status",
        lambda _repo, _source: {
            "source_id": "source", "log_key": "access", "status": "live",
            "last_offset": 123, "last_error": None, "last_event_at": None,
            "lease_owner": "collector-1",
            "lease_expires_at": datetime.now(timezone.utc) - timedelta(seconds=1),
            "updated_at": datetime.now(timezone.utc) - timedelta(seconds=31),
        },
    )

    result = collector.shared_status()

    assert result["status"] == "stale"
    assert result["control_plane_stale"] is True


@pytest.mark.asyncio
async def test_lease_loss_recycles_cycle_without_global_shutdown():
    collector = WebSocketCollector(_config())
    closed = False

    class WebSocket:
        async def close(self):
            nonlocal closed
            closed = True

    collector.session.active_websocket = WebSocket()

    await collector.session.signal_lease_loss("lease lost")

    assert collector.session.lease_lost.is_set()
    assert not collector.stop_event.is_set()
    assert closed
    assert collector.state == "standby"


@pytest.mark.asyncio
async def test_lease_loss_resets_memory_to_durable_offset(monkeypatch):
    collector = WebSocketCollector(_config())
    collector.storage_worker.queue.put_nowait((['line'], 99, 50, "received"))
    collector.storage.pending = [("pending", "received")]
    collector.pending_lines = 1
    collector.storage.stream_offset = 99

    monkeypatch.setattr(collector.session, "load_offset", lambda: 50)

    await collector.session.reset_after_lease_loss()

    assert collector.storage_worker.queue.empty()
    assert collector.storage_worker.queue._unfinished_tasks == 0
    assert collector.storage.pending == []
    assert collector.storage.stream_offset == 50
    assert collector.last_offset == 50


@pytest.mark.asyncio
async def test_checkpoint_rejection_restarts_storage_worker_for_next_batch(monkeypatch):
    from app.db.repositories import CheckpointCommitRejected

    collector = WebSocketCollector(_config())
    calls = 0

    def commit(*_args):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise CheckpointCommitRejected("source", 10)
        return 10, 1, set(), []

    async def mark_lease_lost(_error):
        collector.session.lease_lost.set()

    monkeypatch.setattr(collector, "_commit_batch", commit)
    monkeypatch.setattr(collector.session, "signal_lease_loss", mark_lease_lost)
    collector.storage_worker.start()
    await collector.storage_worker.queue.put((["first"], 10, 0, "stamp"))
    await asyncio.sleep(0)
    await asyncio.wait_for(collector.storage_worker.queue.join(), timeout=1)
    assert collector.storage_worker.task.done()

    await batching.enqueue_storage(collector, ["second"], 10, 0, "stamp")
    await asyncio.wait_for(collector.storage_worker.queue.join(), timeout=1)
    assert calls == 2
    assert not collector.storage_worker.task.done()
    collector.storage_worker.task.cancel()
    await asyncio.gather(collector.storage_worker.task, return_exceptions=True)


@pytest.mark.asyncio
async def test_raw_archive_terminal_failure_fails_receipt_without_hot_loop(tmp_path, monkeypatch):
    from app.services.raw_log_archive import RawArchiveWriteError, RawLogArchive

    archive = RawLogArchive(
        "source", tmp_path, max_write_attempts=2, write_backoff_seconds=0,
    )
    attempts = 0

    def broken_write(_line, _received_at):
        nonlocal attempts
        attempts += 1
        raise OSError("disk full")

    monkeypatch.setattr(archive, "_write_line", broken_write)
    await archive.start()
    with pytest.raises(RawArchiveWriteError):
        await archive.append_batch(["must not be acknowledged"])

    assert attempts == 2
    assert archive.status()["writer_status"] == "FAILED"
    await asyncio.wait_for(archive.stop(), timeout=1)


@pytest.mark.asyncio
async def test_raw_archive_restarts_writer_after_terminal_failure(tmp_path, monkeypatch):
    from app.services.raw_log_archive import RawArchiveWriteError, RawLogArchive

    archive = RawLogArchive("source", tmp_path, max_write_attempts=1, write_backoff_seconds=0)
    broken = True

    def flaky_write(_line, _received_at):
        if broken:
            raise OSError("disk full")

    monkeypatch.setattr(archive, "_write_line", flaky_write)
    await archive.start()
    with pytest.raises(RawArchiveWriteError):
        await archive.append_batch(["first"])

    broken = False
    receipt = await asyncio.wait_for(archive.append_batch(["second"]), timeout=1)
    assert receipt.line_count == 1
    assert archive.status()["writer_status"] == "READY"
    await archive.stop()


@pytest.mark.asyncio
async def test_raw_archive_restart_does_not_duplicate_maintenance_workers(tmp_path, monkeypatch):
    from app.services.raw_log_archive import RawLogArchive

    archive = RawLogArchive("source", tmp_path, max_write_attempts=1, write_backoff_seconds=0)
    maintenance = asyncio.Event()
    compression_task = asyncio.create_task(maintenance.wait())
    upload_task = asyncio.create_task(maintenance.wait())
    archive._compression_task = compression_task
    archive._upload_task = upload_task
    monkeypatch.setattr("app.services.raw_log_archive.shutil.which", lambda name: "/usr/bin/zstd")
    monkeypatch.setattr("app.services.raw_log_archive.BackupSettings.from_env", lambda: object())
    await archive.start()
    assert archive._compression_task is compression_task
    assert archive._upload_task is upload_task
    archive._stop = True
    archive._task.cancel()
    await asyncio.gather(archive._task, return_exceptions=True)
    maintenance.set()
    await asyncio.gather(compression_task, upload_task)
