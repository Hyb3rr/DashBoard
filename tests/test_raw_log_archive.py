import asyncio
from datetime import datetime, timezone
import hashlib
import json
import subprocess
import threading
from types import SimpleNamespace

import pytest

from app.collectors.websocket_collector import CollectorConfig, WebSocketCollector
from app.services.raw_log_archive import RawArchivePressure, RawArchiveUploadError, RawLogArchive
from app.config.backup import BackupSettings


def _read_zstd(path):
    return subprocess.run(["zstd", "-q", "-d", "-c", str(path)], check=True, capture_output=True).stdout


@pytest.mark.asyncio
async def test_upload_initialization_reports_missing_configuration(tmp_path, monkeypatch):
    archive = RawLogArchive("source", tmp_path)
    monkeypatch.setattr(
        "app.services.raw_log_archive.BackupSettings.from_env",
        lambda: (_ for _ in ()).throw(RuntimeError("missing backup configuration")),
    )
    monkeypatch.setattr(
        "app.services.raw_log_archive.azure_sdk_available",
        lambda: (_ for _ in ()).throw(AssertionError("Azure availability must not be checked")),
    )

    dependencies = archive._initialize_uploader()

    assert dependencies is None
    assert archive.status()["upload_status"] == "UNAVAILABLE"
    assert archive.status()["last_error"] == "missing backup configuration"


@pytest.mark.asyncio
async def test_upload_batch_retries_destinations_independently_and_preserves_spool(tmp_path, monkeypatch):
    archive = RawLogArchive("source", tmp_path)
    archive.local_backup_enabled = False
    attempted = []

    def fail_upload(path, *_args):
        attempted.append(path)
        raise OSError("simulated remote failure")

    monkeypatch.setattr(archive, "_upload_sealed", fail_upload)
    monkeypatch.setattr(archive, "_remove_uploaded_artifacts", lambda _path: pytest.fail("failed upload must retain local data"))
    paths = [tmp_path / "source" / f"{name}.log.zst" for name in ("first", "second")]
    for path in paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = path.name.encode()
        path.write_bytes(payload)
        archive._atomic_write_json(path.with_name(path.name + ".json"), {
            "source": "source", "chunk_id": path.stem,
            "compressed_bytes": len(payload), "compressed_sha256": hashlib.sha256(payload).hexdigest(),
        })
    settings = BackupSettings(account="example", container="archive")

    await archive._upload_paths_once(paths, settings, object(), lambda *_args: None)

    assert attempted == paths
    assert archive.status()["upload_status"] == "ERROR"
    assert archive.status()["upload_failures"] == 2
    assert archive.status()["last_error"] == "OSError: simulated remote failure"


class _UploadRecorder:
    def __init__(self, payload):
        self.payload = payload
        self.blocks = []
        self.commits = []
        self.manifests = []
        self.staged = {}
        self.objects = {}

    def put_block(self, key, block_id, data):
        self.blocks.append((key, block_id, data))
        self.staged.setdefault(key, {})[block_id] = data

    def put_block_list(self, key, block_ids):
        self.commits.append((key, block_ids))
        self.objects[key] = b"".join(self.staged[key][block_id] for block_id in block_ids)

    def put_bytes(self, key, data, content_type="application/json"):
        self.manifests.append((key, data, content_type))
        self.objects[key] = data

    def get_bytes(self, key):
        return self.objects.get(key)

    def exists(self, key):
        return key in self.objects


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
async def test_writer_retry_does_not_raise_queue_full_or_kill_worker(tmp_path, monkeypatch):
    archive = RawLogArchive("source", tmp_path, max_queue_lines=1, max_queue_bytes=100)
    attempts = 0

    def flaky_write(_line, _received_at):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise OSError("transient write failure")

    monkeypatch.setattr(archive, "_write_line", flaky_write)
    await archive.start()
    try:
        await archive.append_batch(["retry me"])
        await asyncio.wait_for(archive._queue.join(), timeout=1)
        assert attempts >= 2
        assert archive._task is not None and not archive._task.done()
    finally:
        await archive.stop()


@pytest.mark.asyncio
async def test_inflight_write_failure_cannot_crash_worker_on_full_queue(tmp_path, monkeypatch):
    archive = RawLogArchive("source", tmp_path, max_queue_lines=1, max_queue_bytes=100)
    write_started = threading.Event()
    allow_failure = threading.Event()
    writes = []

    def blocked_write(line, _received_at):
        writes.append(line)
        if line == "first" and writes.count("first") == 1:
            write_started.set()
            allow_failure.wait(timeout=1)
            raise OSError("forced write failure")

    monkeypatch.setattr(archive, "_write_line", blocked_write)
    await archive.start()
    try:
        archive.tap(["first"])
        await asyncio.wait_for(asyncio.to_thread(write_started.wait, 1), timeout=1)

        archive.tap(["second"])
        assert archive._queue.full()

        allow_failure.set()
        await asyncio.wait_for(archive._queue.join(), timeout=1)

        assert writes == ["first", "first", "second"]
        assert archive._task is not None and not archive._task.done()
        assert archive.status()["failed_writes"] == 1
    finally:
        allow_failure.set()
        tasks = [archive._task, archive._compression_task, archive._upload_task, archive._disk_monitor_task]
        for task in tasks:
            if task and not task.done():
                task.cancel()
        await asyncio.gather(*(task for task in tasks if task), return_exceptions=True)
        if archive._task and archive._task.done() and not archive._task.cancelled():
            archive._task.exception()
        archive._task = archive._compression_task = archive._upload_task = archive._disk_monitor_task = None


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
    from app.collectors import batching
    from app.collectors.websocket_collector import utc_now

    await batching.handle_message(collector, '{"type":"lines","items":["raw-line"]}', 0, utc_now)
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
    first_tasks = [first._task, first._compression_task, first._upload_task, first._disk_monitor_task]
    for task in first_tasks:
        if task and not task.done():
            task.cancel()
    await asyncio.gather(*(task for task in first_tasks if task), return_exceptions=True)
    first._task = first._compression_task = first._upload_task = first._disk_monitor_task = None

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


@pytest.mark.asyncio
async def test_concurrent_stop_is_idempotent_and_seals_once(tmp_path, monkeypatch):
    monkeypatch.setattr("app.services.raw_log_archive.shutil.which", lambda _name: None)
    archive = RawLogArchive("source", tmp_path)
    await archive.start()
    archive.tap(["one"], datetime(2026, 8, 29, 12, tzinfo=timezone.utc))
    await archive._queue.join()
    await asyncio.gather(archive.stop(), archive.stop())
    chunks = list(tmp_path.rglob("*.log"))
    assert len(chunks) == 1
    assert chunks[0].read_text() == "one\n"
    assert archive.status()["active_chunk"] is None


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


def test_upload_sealed_recovers_matching_remote_manifest_without_reupload(tmp_path):
    path = tmp_path / "source" / "2026" / "08" / "29" / "20260829T120000Z-000001.log.zst"
    path.parent.mkdir(parents=True)
    payload = b"compressed-payload"
    path.write_bytes(payload)
    settings = BackupSettings("account", "container")
    uploader = _UploadRecorder(payload)
    object_key = f"{settings.prefix}/raw-logs/{path.relative_to(tmp_path).as_posix()}"
    manifest_key = f"{settings.prefix}/raw-logs/manifests/source/{path.stem}.json"
    manifest = {
        "schema_version": 1, "source": "source", "chunk_id": path.stem,
        "object_key": object_key, "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(), "status": "completed",
        "verified_at": "2026-08-29T12:00:00+00:00",
    }
    uploader.objects[object_key] = payload
    uploader.objects[manifest_key] = json.dumps(manifest).encode()

    result = RawLogArchive._upload_sealed(
        path, tmp_path, "source", settings, uploader,
        lambda _settings, _key: (len(payload), hashlib.sha256(payload).hexdigest()),
    )

    assert result == manifest
    assert uploader.blocks == []
    assert uploader.commits == []


def test_upload_sealed_recovers_matching_object_when_manifest_is_missing(tmp_path):
    path = tmp_path / "source" / "2026" / "08" / "29" / "20260829T120000Z-000001.log.zst"
    path.parent.mkdir(parents=True)
    payload = b"compressed-payload"
    digest = hashlib.sha256(payload).hexdigest()
    path.write_bytes(payload)
    settings = BackupSettings("account", "container")
    uploader = _UploadRecorder(payload)
    object_key = f"{settings.prefix}/raw-logs/{path.relative_to(tmp_path).as_posix()}"
    manifest_key = f"{settings.prefix}/raw-logs/manifests/source/{path.stem}.json"
    uploader.objects[object_key] = payload

    result = RawLogArchive._upload_sealed(
        path, tmp_path, "source", settings, uploader,
        lambda _settings, key: (len(payload), digest) if key == object_key else None,
    )

    assert result["source"] == "source"
    assert result["chunk_id"] == path.stem
    assert result["object_key"] == object_key
    assert result["bytes"] == len(payload)
    assert result["sha256"] == digest
    assert result["status"] == "completed"
    assert uploader.get_bytes(manifest_key) is not None
    assert uploader.blocks == []
    assert uploader.commits == []


def test_upload_sealed_rejects_conflicting_existing_object_without_overwrite(tmp_path):
    path = tmp_path / "source" / "2026" / "08" / "29" / "20260829T120000Z-000001.log.zst"
    path.parent.mkdir(parents=True)
    payload = b"compressed-payload"
    path.write_bytes(payload)
    settings = BackupSettings("account", "container")
    uploader = _UploadRecorder(payload)
    object_key = f"{settings.prefix}/raw-logs/{path.relative_to(tmp_path).as_posix()}"
    manifest_key = f"{settings.prefix}/raw-logs/manifests/source/{path.stem}.json"
    conflicting = b"different-object"
    uploader.objects[object_key] = conflicting

    with pytest.raises(RawArchiveUploadError, match="object conflicts"):
        RawLogArchive._upload_sealed(
            path, tmp_path, "source", settings, uploader,
            lambda _settings, _key: (len(conflicting), hashlib.sha256(conflicting).hexdigest()),
        )

    assert uploader.objects[object_key] == conflicting
    assert uploader.get_bytes(manifest_key) is None
    assert uploader.blocks == []
    assert uploader.commits == []


def test_upload_sealed_rejects_conflicting_existing_manifest_without_overwrite(tmp_path):
    path = tmp_path / "source" / "2026" / "08" / "29" / "20260829T120000Z-000001.log.zst"
    path.parent.mkdir(parents=True)
    payload = b"compressed-payload"
    digest = hashlib.sha256(payload).hexdigest()
    path.write_bytes(payload)
    settings = BackupSettings("account", "container")
    uploader = _UploadRecorder(payload)
    object_key = f"{settings.prefix}/raw-logs/{path.relative_to(tmp_path).as_posix()}"
    manifest_key = f"{settings.prefix}/raw-logs/manifests/source/{path.stem}.json"
    existing_manifest = json.dumps({
        "schema_version": 1, "source": "source", "chunk_id": path.stem,
        "object_key": object_key, "bytes": len(payload),
        "sha256": "0" * 64, "status": "completed",
    }).encode()
    uploader.objects[manifest_key] = existing_manifest

    with pytest.raises(RawArchiveUploadError, match="manifest conflicts"):
        RawLogArchive._upload_sealed(
            path, tmp_path, "source", settings, uploader,
            lambda _settings, _key: (len(payload), digest),
        )

    assert uploader.get_bytes(manifest_key) == existing_manifest
    assert path.read_bytes() == payload
    assert uploader.blocks == []
    assert uploader.commits == []


def test_local_copy_requires_reserve_plus_size_but_reuses_verified_copy_at_reserve(tmp_path, monkeypatch):
    spool = tmp_path / "spool"
    backup = tmp_path / "backup"
    archive = RawLogArchive("source", spool)
    archive.local_backup_dir = backup
    archive.disk_min_free_bytes = 100
    path = spool / "source" / "2026" / "08" / "29" / "20260829T120000Z-000001.log.zst"
    path.parent.mkdir(parents=True)
    payload = b"x" * 50
    path.write_bytes(payload)
    identity = {"bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
    state = {
        "source": "source", "chunk_id": path.stem, **identity,
        "local": {"status": "pending"},
    }
    free_bytes = 149
    monkeypatch.setattr(
        "app.services.raw_log_archive.shutil.disk_usage",
        lambda _path: SimpleNamespace(free=free_bytes),
    )

    with pytest.raises(RawArchivePressure, match="free-space reserve"):
        archive._ensure_local_copy(path, state)

    target = backup / path.relative_to(spool)
    assert path.exists()
    assert not target.exists()
    assert not target.with_name(target.name + ".tmp").exists()
    assert state["local"]["status"] == "pending"

    free_bytes = 100
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(payload)
    result = archive._ensure_local_copy(path, state)

    assert result["status"] == "verified"
    assert result["sha256"] == identity["sha256"]


def test_local_copy_verification_failure_removes_temporary_file_and_preserves_spool(tmp_path, monkeypatch):
    spool = tmp_path / "spool"
    backup = tmp_path / "backup"
    archive = RawLogArchive("source", spool)
    archive.local_backup_dir = backup
    archive.disk_min_free_bytes = 0
    path = spool / "source" / "2026" / "08" / "29" / "20260829T120000Z-000001.log.zst"
    path.parent.mkdir(parents=True)
    payload = b"verified-source-payload"
    digest = hashlib.sha256(payload).hexdigest()
    path.write_bytes(payload)
    state = {"bytes": len(payload), "sha256": digest, "local": {"status": "pending"}}
    target = backup / path.relative_to(spool)
    temporary = target.with_name(target.name + ".tmp")
    identity_checks = []

    def identity(candidate):
        identity_checks.append(candidate)
        if candidate == path:
            return len(payload), digest
        if candidate == temporary:
            assert not target.exists()
            return len(payload), "0" * 64
        return RawLogArchive._file_identity(candidate)

    monkeypatch.setattr(archive, "_file_identity", identity)

    with pytest.raises(RawArchiveUploadError, match="checksum mismatch"):
        archive._ensure_local_copy(path, state)

    assert temporary in identity_checks
    assert not target.exists()
    assert not temporary.exists()
    assert path.read_bytes() == payload
    assert state["local"]["status"] == "pending"


def test_local_copy_rejects_conflicting_existing_target_without_overwrite(tmp_path):
    spool = tmp_path / "spool"
    backup = tmp_path / "backup"
    archive = RawLogArchive("source", spool)
    archive.local_backup_dir = backup
    archive.disk_min_free_bytes = 0
    path = spool / "source" / "2026" / "08" / "29" / "20260829T120000Z-000001.log.zst"
    path.parent.mkdir(parents=True)
    payload = b"verified-source-payload"
    path.write_bytes(payload)
    state = {
        "bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest(),
        "local": {"status": "pending"},
    }
    target = backup / path.relative_to(spool)
    target.parent.mkdir(parents=True)
    conflicting = b"existing-different-copy"
    target.write_bytes(conflicting)

    with pytest.raises(RawArchiveUploadError, match="existing local backup conflicts"):
        archive._ensure_local_copy(path, state)

    assert target.read_bytes() == conflicting
    assert path.read_bytes() == payload
    assert state["local"]["status"] == "pending"


@pytest.mark.asyncio
async def test_local_and_azure_destination_retries_are_independent(tmp_path, monkeypatch):
    spool = tmp_path / "spool"
    backup = tmp_path / "backup"
    archive = RawLogArchive("source", spool)
    archive.local_backup_dir = backup
    archive.disk_min_free_bytes = 0
    path = spool / "source" / "2026" / "08" / "29" / "20260829T120000Z-000001.log.zst"
    path.parent.mkdir(parents=True)
    payload = b"compressed-payload"
    path.write_bytes(payload)
    marker = {
        "source": "source", "chunk_id": "20260829T120000Z-000001",
        "compressed_bytes": len(payload), "compressed_sha256": hashlib.sha256(payload).hexdigest(),
    }
    archive._atomic_write_json(path.with_name(path.name + ".json"), marker)
    state = {
        "schema_version": 1, "source": "source", "chunk_id": marker["chunk_id"],
        "bytes": len(payload), "sha256": marker["compressed_sha256"],
        "local": {"status": "pending"}, "azure": {"status": "pending"},
    }
    archive._write_chunk_state(path, state)
    settings = BackupSettings("account", "container")
    uploader = _UploadRecorder(payload)

    def fail_azure(*_args):
        raise OSError("Azure unavailable")

    monkeypatch.setattr(archive, "_upload_sealed", fail_azure)
    await archive._upload_paths_once([path], settings, uploader, lambda *_args: None)
    state = json.loads(archive._state_path(path).read_text())
    local_path = backup / path.relative_to(spool)
    assert local_path.read_bytes() == payload
    assert state["local"]["status"] == "verified"
    assert state["azure"]["status"] == "failed"

    uploaded = []

    def succeed_azure(*_args):
        uploaded.append(True)
        return {
            "source": "source", "chunk_id": path.stem, "object_key": "raw/object",
            "bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest(),
            "verified_at": "2026-08-29T12:00:00+00:00", "status": "completed",
        }

    monkeypatch.setattr(archive, "_upload_sealed", succeed_azure)
    await archive._upload_paths_once([path], settings, uploader, lambda *_args: None)

    assert uploaded == [True]
    assert not path.exists()
    assert json.loads(archive._manifest_path(local_path).read_text())["azure"]["status"] == "verified"


@pytest.mark.asyncio
async def test_unavailable_azure_waits_before_retrying_verified_local_chunk(tmp_path, monkeypatch):
    spool = tmp_path / "spool"
    backup = tmp_path / "backup"
    archive = RawLogArchive("source", spool)
    archive.local_backup_enabled = True
    archive.local_backup_dir = backup
    archive.disk_min_free_bytes = 0
    path = spool / "source" / "2026" / "08" / "29" / "20260829T120000Z-000001.log.zst"
    path.parent.mkdir(parents=True)
    payload = b"compressed-payload"
    digest = hashlib.sha256(payload).hexdigest()
    path.write_bytes(payload)
    marker = {
        "source": "source", "chunk_id": path.stem,
        "compressed_bytes": len(payload), "compressed_sha256": digest,
    }
    archive._atomic_write_json(path.with_name(path.name + ".json"), marker)
    archive._write_chunk_state(path, {
        "schema_version": 1, "source": "source", "chunk_id": path.stem,
        "bytes": len(payload), "sha256": digest,
        "local": {"status": "pending"}, "azure": {"status": "pending"},
    })

    scans = []
    copies = []
    sleeps = []
    original_scan = archive._upload_paths
    original_copy = archive._ensure_local_copy

    def record_scan():
        scans.append(True)
        return original_scan()

    def record_copy(chunk_path, state):
        copies.append(chunk_path)
        return original_copy(chunk_path, state)

    async def stop_at_backoff(seconds):
        sleeps.append(seconds)
        persisted = json.loads(archive._state_path(path).read_text())
        assert scans == [True]
        assert persisted["local"]["status"] == "verified"
        assert persisted["azure"]["status"] == "pending"
        archive._stop = True

    monkeypatch.setattr(archive, "_initialize_uploader", lambda: None)
    monkeypatch.setattr(archive, "_upload_paths", record_scan)
    monkeypatch.setattr(archive, "_ensure_local_copy", record_copy)
    monkeypatch.setattr(archive, "_run_local_retention", lambda: None)
    monkeypatch.setattr(archive, "_remove_uploaded_artifacts", lambda _path: pytest.fail("spool cleanup must wait for Azure"))
    monkeypatch.setattr("app.services.raw_log_archive.asyncio.sleep", stop_at_backoff)

    await archive._upload_loop()

    state = json.loads(archive._state_path(path).read_text())
    local_path = backup / path.relative_to(spool)
    assert sleeps == [1]
    assert scans == [True]
    assert copies == [path]
    assert state["local"]["status"] == "verified"
    assert state["azure"]["status"] == "pending"
    assert path.read_bytes() == payload
    assert local_path.read_bytes() == payload
    assert not archive._manifest_path(local_path).exists()


@pytest.mark.asyncio
async def test_unavailable_azure_backs_off_for_failed_state_without_recopy(tmp_path, monkeypatch):
    spool = tmp_path / "spool"
    backup = tmp_path / "backup"
    archive = RawLogArchive("source", spool)
    archive.local_backup_enabled = True
    archive.local_backup_dir = backup
    archive.disk_min_free_bytes = 0
    path = spool / "source" / "2026" / "08" / "29" / "20260829T120000Z-000001.log.zst"
    path.parent.mkdir(parents=True)
    payload = b"compressed-payload"
    digest = hashlib.sha256(payload).hexdigest()
    path.write_bytes(payload)
    marker = {
        "source": "source", "chunk_id": path.stem,
        "compressed_bytes": len(payload), "compressed_sha256": digest,
    }
    archive._atomic_write_json(path.with_name(path.name + ".json"), marker)
    archive._write_chunk_state(path, {
        "schema_version": 1, "source": "source", "chunk_id": path.stem,
        "bytes": len(payload), "sha256": digest,
        "local": {"status": "verified", "path": str(backup / path.relative_to(spool)),
                  "bytes": len(payload), "sha256": digest},
        "azure": {"status": "failed", "last_error": "prior Azure outage"},
    })
    local_path = backup / path.relative_to(spool)
    local_path.parent.mkdir(parents=True)
    local_path.write_bytes(payload)

    scans = []
    sleeps = []

    def record_scan():
        scans.append(True)
        return [path]

    async def stop_at_backoff(seconds):
        sleeps.append(seconds)
        persisted = json.loads(archive._state_path(path).read_text())
        assert scans == [True]
        assert persisted["local"]["status"] == "verified"
        assert persisted["azure"]["status"] == "failed"
        assert persisted["azure"]["last_error"] == "prior Azure outage"
        archive._stop = True

    monkeypatch.setattr(archive, "_initialize_uploader", lambda: None)
    monkeypatch.setattr(archive, "_upload_paths", record_scan)
    monkeypatch.setattr(archive, "_ensure_local_copy", lambda *_args: pytest.fail("verified local copy must not be repeated"))
    monkeypatch.setattr(archive, "_run_local_retention", lambda: None)
    monkeypatch.setattr(archive, "_remove_uploaded_artifacts", lambda _path: pytest.fail("spool cleanup must wait for Azure"))
    monkeypatch.setattr("app.services.raw_log_archive.asyncio.sleep", stop_at_backoff)

    await archive._upload_loop()

    state = json.loads(archive._state_path(path).read_text())
    assert sleeps == [1]
    assert scans == [True]
    assert state["local"]["status"] == "verified"
    assert state["azure"]["status"] == "failed"
    assert state["azure"]["last_error"] == "prior Azure outage"
    assert path.read_bytes() == payload
    assert local_path.read_bytes() == payload
    assert not archive._manifest_path(local_path).exists()


def test_local_retention_requires_verified_azure_and_matching_checksum(tmp_path):
    archive = RawLogArchive("source", tmp_path / "spool")
    archive.local_backup_dir = tmp_path / "backup"
    archive.local_retention_days = 1
    expired = datetime.now(timezone.utc).timestamp() - 3 * 86400
    old = datetime.fromtimestamp(expired, timezone.utc).isoformat()
    for name, azure_status, corrupt in (("eligible", "verified", False), ("pending", "pending", False), ("tampered", "verified", True)):
        path = archive.local_backup_dir / "source" / f"{name}.log.zst"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"changed" if corrupt else b"chunk")
        archive._atomic_write_json(archive._manifest_path(path), {
            "created_at": old, "bytes": 5, "sha256": hashlib.sha256(b"chunk").hexdigest(),
            "local": {"status": "verified"}, "azure": {"status": azure_status},
        })

    archive._run_local_retention()

    assert not (archive.local_backup_dir / "source" / "eligible.log.zst").exists()
    assert (archive.local_backup_dir / "source" / "pending.log.zst").exists()
    assert (archive.local_backup_dir / "source" / "tampered.log.zst").exists()


@pytest.mark.asyncio
async def test_disk_pressure_blocks_admission_and_recovers_from_cached_refresh(tmp_path, monkeypatch):
    archive = RawLogArchive("source", tmp_path / "spool")
    archive.local_backup_enabled = False
    archive.disk_min_free_bytes = 100
    archive._spool_free_bytes = 150
    archive._pending_bytes = 60

    with pytest.raises(RawArchivePressure, match="reserved"):
        await archive.append_batch(["must not enter queue"])
    assert archive.status()["pending_lines"] == 0
    assert archive.status()["writer_status"] == "FAILED"

    usage = SimpleNamespace(free=500)
    monkeypatch.setattr("app.services.raw_log_archive.shutil.disk_usage", lambda _path: usage)
    await asyncio.to_thread(archive._refresh_disk_pressure)

    assert archive.status()["disk_pressure_state"] == "NORMAL"
    assert archive.status()["writer_status"] == "READY"
