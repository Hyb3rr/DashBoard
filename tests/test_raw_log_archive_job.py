import asyncio
import json

from app.config.backup import BackupSettings
from app.services import raw_log_archive
from app.services.raw_log_archive import RawLogArchive
from scripts.ops.raw_log_archive_job import RunLock, run_once


def test_job_runs_once_and_releases_lock(tmp_path, monkeypatch):
    calls = []

    class FakeArchive:
        def __init__(self, source_id, spool):
            calls.append((source_id, spool))

        async def maintenance_once(self):
            return {"pending_lines": 0}

    result = run_once(tmp_path, archive_factory=FakeArchive)
    assert result == {"pending_lines": 0, "status": "completed"}
    assert calls == [("scheduled", tmp_path)]
    assert not (tmp_path / ".raw-archive-job.lock").exists()


def test_job_reports_active_lock(tmp_path):
    lock = RunLock(tmp_path / "lock")
    assert lock.acquire()
    try:
        assert run_once(tmp_path, tmp_path / "lock") == {"status": "locked"}
    finally:
        lock.release()


def test_job_propagates_maintenance_failure_and_releases_lock(tmp_path):
    class FailingArchive:
        def __init__(self, *_):
            pass

        async def maintenance_once(self):
            await asyncio.sleep(0)
            raise RuntimeError("maintenance failed")

    try:
        run_once(tmp_path, archive_factory=FailingArchive)
    except RuntimeError as exc:
        assert str(exc) == "maintenance failed"
    else:
        raise AssertionError("expected maintenance failure")
    assert not (tmp_path / ".raw-archive-job.lock").exists()


def test_maintenance_upload_failure_is_one_shot_and_preserves_artifact(tmp_path, monkeypatch):
    compressed = tmp_path / "source" / "2026" / "09" / "03" / "20260903T130000Z-000001.log.zst"
    compressed.parent.mkdir(parents=True)
    compressed.write_bytes(b"compressed")
    compressed.with_name(compressed.name + ".json").write_text("{}\n")
    attempts = []

    class Uploader:
        def __init__(self):
            self.closed = 0

        def close(self):
            self.closed += 1

    uploader = Uploader()

    monkeypatch.setattr(raw_log_archive.BackupSettings, "from_env", classmethod(lambda cls: BackupSettings("account", "container")))
    monkeypatch.setattr(raw_log_archive, "azure_sdk_available", lambda: True)
    monkeypatch.setattr(raw_log_archive, "create_azure_uploader", lambda _settings: (uploader, lambda *_args: None))

    def fail_upload(*_args):
        attempts.append(compressed)
        raise RuntimeError("Azure unavailable")

    monkeypatch.setattr(RawLogArchive, "_upload_sealed", staticmethod(fail_upload))
    archive = RawLogArchive("source", tmp_path)

    first = asyncio.run(asyncio.wait_for(archive.maintenance_once(), timeout=0.5))
    second = asyncio.run(asyncio.wait_for(RawLogArchive("source", tmp_path).maintenance_once(), timeout=0.5))

    assert first["upload_failures"] == 1
    assert second["upload_failures"] == 1
    assert len(attempts) == 2
    assert compressed.exists()
    assert compressed.with_name(compressed.name + ".json").exists()
    assert uploader.closed == 2


def test_maintenance_compression_failure_is_one_shot_and_preserves_payload(tmp_path, monkeypatch):
    payload = tmp_path / "source" / "2026" / "09" / "03" / "20260903T130000Z-000001.log"
    payload.parent.mkdir(parents=True)
    payload.write_bytes(b"raw")
    payload.with_suffix(".json").write_text(json.dumps({"status": "SEALED"}) + "\n")
    attempts = []

    def fail_compression(_path):
        attempts.append(True)
        raise RuntimeError("compression unavailable")

    monkeypatch.setattr(RawLogArchive, "_compress_and_verify", staticmethod(fail_compression))
    result = asyncio.run(asyncio.wait_for(RawLogArchive("source", tmp_path).maintenance_once(), timeout=0.5))

    assert result["compression_failures"] == 1
    assert attempts == [True]
    assert payload.exists()
