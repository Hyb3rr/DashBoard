import asyncio

from scripts.ops.raw_log_archive_scheduler import run_once


def test_scheduler_uses_single_run_lock(tmp_path, monkeypatch):
    calls = []

    async def maintenance(self):
        calls.append(self.source_id)
        return {"pending_lines": 0}

    monkeypatch.setattr("scripts.ops.raw_log_archive_scheduler.RawLogArchive.maintenance_once", maintenance)
    first = run_once(tmp_path)
    assert first["status"] == "completed"
    assert calls == ["scheduled"]


def test_scheduler_does_not_change_source_when_no_artifacts(tmp_path, monkeypatch):
    before = sorted(path.relative_to(tmp_path) for path in tmp_path.rglob("*"))
    monkeypatch.setattr("scripts.ops.raw_log_archive_scheduler.RawLogArchive.maintenance_once", lambda self: asyncio.sleep(0, result={"pending_lines": 0}))
    result = run_once(tmp_path)
    after = sorted(path.relative_to(tmp_path) for path in tmp_path.rglob("*") if path.name != ".raw-archive-maintenance.lock")
    assert result["status"] == "completed"
    assert after == before
