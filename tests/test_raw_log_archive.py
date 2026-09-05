import asyncio
from datetime import datetime, timezone
import hashlib
import json
import subprocess

import pytest

from app.collectors.websocket_collector import CollectorConfig, WebSocketCollector
from app.services.raw_log_archive import RawArchivePressure, RawLogArchive
from app.config.backup import BackupSettings


def _read_zstd(path):
    return subprocess.run(["zstd", "-q", "-d", "-c", str(path)], check=True, capture_output=True).stdout


class _UploadRecorder:
    def __init__(self, payload):
        self.payload = payload
        self.blocks = []
        self.commits = []
        self.manifests = []

    def put_block(self, key, block_id, data):
        self.blocks.append((key, block_id, data))

    def put_block_list(self, key, block_ids):
        self.commits.append((key, block_ids))

    def put_bytes(self, key, data, content_type="application/json"):
        self.manifests.append((key, data, content_type))


def test_azure_uploader_close_is_idempotent():
    pytest.importorskip(
        "azure.core.pipeline.policies",
        reason="Azure backup test requires optional Azure SDK",
    )
    from scripts.ops.backup_postgres import AzureBlobUploader

    class Service:
        def __init__(self):
            self.closed = 0

        def get_container_client(self, _name):
            return object()

        def close(self):
            self.closed += 1

    service = Service()
    uploader = AzureBlobUploader(BackupSettings("account", "container"), blob_service=service, credential=object())
    uploader.close()
    uploader.close()
    assert service.closed == 1


@pytest.mark.asyncio
async def test_tap_is_immediate_and_writer_preserves_raw_payload(tmp_path):
    archive = RawLogArchive("azure-access", tmp_path)
    await archive.start()
    try:
        lines = ['203.0.113.10 "GET /.env HTTP/1.1" 404', "raw unicode café"]
        assert archive.tap(lines) == 2
        assert archive.status()["pending_lines"] == 2
        await asyncio.wait_for(archive._queue.join(), timeout=1)
        await archive.stop()
        files = list(tmp_path.rglob("*.log.zst"))
        assert len(files) == 1
        assert _read_zstd(files[0]) == ("\n".join(lines) + "\n").encode("utf-8")
        assert archive.status()["written_lines"] == 2
        assert archive.status()["pending_lines"] == 0
        metadata = json.loads(files[0].with_name(files[0].name + ".json").read_text())
        assert metadata["status"] == "VERIFIED"
        assert metadata["line_count"] == 2
        assert metadata["original_bytes"] == len(("\n".join(lines) + "\n").encode("utf-8"))
    finally:
        if archive._task:
            await archive.stop()


@pytest.mark.asyncio
async def test_append_batch_receipt_and_parse_failure_sidecar_are_durable(tmp_path, monkeypatch):
    monkeypatch.setattr("app.services.raw_log_archive.shutil.which", lambda _name: None)
    archive = RawLogArchive("source", tmp_path)
    await archive.start()
    try:
        receipt = await archive.append_batch(["not an access log"])
        assert receipt.status == "RAW_DURABLE"
        assert receipt.line_count == 1
        assert receipt.raw_bytes == len(b"not an access log\n")
        failure = {
            "source_id": "source", "source_offset": 0,
            "raw_sha256": hashlib.sha256(b"not an access log").hexdigest(),
            "parser_error_code": "INVALID_APACHE_COMBINED_FORMAT",
            "parser_error_message": "line does not match Apache Combined format",
            "parser_version": "apache-combined-v1", "observed_at": "2026-08-31T00:00:00+00:00",
        }
        archive.write_parse_failures([failure])
        archive.write_parse_failures([failure])
        await archive.stop()
        sidecars = list(tmp_path.rglob("*.parse-failures.jsonl"))
        assert len(sidecars) == 1
        assert len(sidecars[0].read_text(encoding="utf-8").splitlines()) == 1
    finally:
        if archive._task:
            await archive.stop()


def test_slow_or_unstarted_writer_does_not_drop_payload(tmp_path):
    archive = RawLogArchive("source", tmp_path)
    lines = ["first", "second", "third"]
    assert archive.tap(lines) == 3
    assert archive.status()["pending_lines"] == 3
    assert archive.status()["pending_bytes"] == sum(len(line.encode()) + 1 for line in lines)


def test_queue_capacity_refuses_whole_batch_without_silent_drop(tmp_path):
    archive = RawLogArchive("source", tmp_path, max_queue_lines=2, max_queue_bytes=100)
    archive.tap(["first", "second"])
    with pytest.raises(RawArchivePressure, match="capacity"):
        archive.tap(["third"])
    assert archive.status()["pending_lines"] == 2
    assert archive.status()["pressure_state"] == "CRITICAL"
    assert archive.status()["queue_capacity_lines"] == 2
    assert archive.status()["queue_capacity_bytes"] == 100


def test_queue_byte_capacity_refuses_batch_atomically(tmp_path):
    archive = RawLogArchive("source", tmp_path, max_queue_lines=10, max_queue_bytes=6)
    with pytest.raises(RawArchivePressure):
        archive.tap(["one", "two"])
    assert archive.status()["pending_lines"] == 0


@pytest.mark.asyncio
async def test_collector_taps_before_detection_and_storage(monkeypatch, tmp_path):
    collector = WebSocketCollector(
        CollectorConfig(True, "wss://example.test", "secret", "access", "source", 200, 1000, 300)
    )
    calls = []

    class Tap:
        async def append_batch(self, lines, received_at=None):
            calls.append(("tap", list(lines)))
            return None

        def tap(self, lines):
            calls.append(("tap", list(lines)))

        def status(self):
            return {"pending_lines": 0, "pending_bytes": 0, "written_lines": 0,
                    "written_bytes": 0, "failed_writes": 0, "last_error": None}

    collector._raw_archive = Tap()
    monkeypatch.setattr(collector._window_detector, "observe", lambda line: calls.append(("detect", line)) or [])
    await collector.handle_message('{"type":"lines","items":["raw-line"]}', 0)
    assert calls == [("tap", ["raw-line"]), ("detect", "raw-line")]


def test_archive_path_is_source_and_utc_hour(tmp_path):
    archive = RawLogArchive("azure/access", tmp_path)
    path = archive._directory(datetime(2026, 8, 29, 12, 34, tzinfo=timezone.utc)
    )
    assert path == tmp_path / "azure_access" / "2026" / "08" / "29"


@pytest.mark.asyncio
async def test_hour_rollover_seals_old_chunk(tmp_path, monkeypatch):
    monkeypatch.setattr("app.services.raw_log_archive.shutil.which", lambda _name: None)
    archive = RawLogArchive("source", tmp_path, max_chunk_bytes=1024)
    await archive.start()
    archive.tap(["one"], datetime(2026, 8, 29, 12, 59, tzinfo=timezone.utc))
    archive.tap(["two"], datetime(2026, 8, 29, 13, 0, tzinfo=timezone.utc))
    await archive._queue.join()
    await archive.stop()
    chunks = sorted(tmp_path.rglob("*.log"))
    assert [chunk.read_text() for chunk in chunks] == ["one\n", "two\n"]
    assert all(json.loads(chunk.with_suffix(".json").read_text())["status"] == "SEALED" for chunk in chunks)


@pytest.mark.asyncio
async def test_size_rollover_keeps_sealed_chunk_immutable(tmp_path, monkeypatch):
    monkeypatch.setattr("app.services.raw_log_archive.shutil.which", lambda _name: None)
    archive = RawLogArchive("source", tmp_path, max_chunk_bytes=6)
    await archive.start()
    archive.tap(["one", "two", "three"], datetime(2026, 8, 29, 12, tzinfo=timezone.utc))
    await archive._queue.join()
    chunks = sorted(tmp_path.rglob("*.log"))
    assert [chunk.read_text() for chunk in chunks] == ["one\n", "two\n"]
    first_bytes = chunks[0].read_bytes()
    archive.tap(["later"], datetime(2026, 8, 29, 12, tzinfo=timezone.utc))
    await archive._queue.join()
    assert chunks[0].read_bytes() == first_bytes
    await archive.stop()


@pytest.mark.asyncio
async def test_restart_recovers_active_chunk_and_preserves_order(tmp_path, monkeypatch):
    monkeypatch.setattr("app.services.raw_log_archive.shutil.which", lambda _name: None)
    stamp = datetime(2026, 8, 29, 12, tzinfo=timezone.utc)
    first = RawLogArchive("source", tmp_path)
    await first.start()
    first.tap(["one", "two"], stamp)
    await first._queue.join()
    first._task.cancel()
    await asyncio.gather(first._task, return_exceptions=True)

    second = RawLogArchive("source", tmp_path)
    await second.start()
    second.tap(["three"], stamp)
    await second._queue.join()
    await second.stop()
    chunks = sorted(tmp_path.rglob("*.log"))
    assert len(chunks) == 1
    assert chunks[0].read_text() == "one\ntwo\nthree\n"


@pytest.mark.asyncio
async def test_restart_advances_sequence_after_sealed_chunk(tmp_path, monkeypatch):
    monkeypatch.setattr("app.services.raw_log_archive.shutil.which", lambda _name: None)
    stamp = datetime(2026, 8, 29, 12, tzinfo=timezone.utc)
    first = RawLogArchive("source", tmp_path, max_chunk_bytes=4)
    await first.start()
    first.tap(["one", "two"], stamp)
    await first._queue.join()
    await first.stop()
    old_ids = {json.loads(path.with_suffix(".json").read_text())["chunk_id"] for path in tmp_path.rglob("*.log")}

    second = RawLogArchive("source", tmp_path, max_chunk_bytes=4)
    await second.start()
    second.tap(["new"], stamp)
    await second._queue.join()
    await second.stop()
    all_ids = {json.loads(path.with_suffix(".json").read_text())["chunk_id"] for path in tmp_path.rglob("*.log")}
    new_ids = all_ids - old_ids
    assert len(all_ids) == 3
    assert len(new_ids) == 1
    assert int(next(iter(new_ids)).rsplit("-", 1)[1]) > max(int(item.rsplit("-", 1)[1]) for item in old_ids)


@pytest.mark.asyncio
async def test_sealed_chunk_is_zstd_compressed_verified_and_original_removed(tmp_path):
    archive = RawLogArchive("source", tmp_path, max_chunk_bytes=1024)
    await archive.start()
    archive.tap(["one", "two"], datetime(2026, 8, 29, 12, tzinfo=timezone.utc))
    await archive._queue.join()
    await archive.stop()
    compressed = list(tmp_path.rglob("*.log.zst"))
    assert len(compressed) == 1
    assert not list(tmp_path.rglob("*.log"))
    metadata = json.loads(compressed[0].with_name(compressed[0].name + ".json").read_text())
    assert metadata["status"] == "VERIFIED"
    assert metadata["original_bytes"] == len(b"one\ntwo\n")
    assert metadata["original_sha256"] == hashlib.sha256(b"one\ntwo\n").hexdigest()


def test_upload_sealed_zstd_streams_blocks_verifies_and_writes_manifest(tmp_path):
    path = tmp_path / "source" / "2026" / "08" / "29" / "20260829T120000Z-000001.log.zst"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"compressed-payload")
    settings = BackupSettings("account", "container", part_size=5)
    uploader = _UploadRecorder(path.read_bytes())
    result = RawLogArchive._upload_sealed(
        path, tmp_path, "source", settings, uploader,
        lambda _settings, _key: (len(path.read_bytes()), hashlib.sha256(path.read_bytes()).hexdigest()),
    )
    assert [item[2] for item in uploader.blocks] == [b"compr", b"essed", b"-payl", b"oad"]
    assert len(uploader.commits) == 1
    assert uploader.manifests[0][0].endswith("raw-logs/manifests/source/20260829T120000Z-000001.log.json")
    assert result["status"] == "completed"
