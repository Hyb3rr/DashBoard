import json
from datetime import datetime, timezone

from app.tools import data_scheduler, worldbank_update


def _records(code, value=1):
    return [{"countryiso3code": "USA", "country": {"value": "United States"}, "date": "2025", "value": value}]


def test_worldbank_update_validates_and_atomically_writes(tmp_path, monkeypatch):
    target = tmp_path / "Data.csv"
    target.write_text("last good\n")
    monkeypatch.setattr(worldbank_update, "_fetch", lambda code, timeout: _records(code))
    result = worldbank_update.update_world_bank(target, min_country_count=1, refresh_market=False)
    assert result["status"] == "updated"
    assert "Country Code" in target.read_text()
    assert (tmp_path / "Data.last-good.csv").read_text() == "last good\n"


def test_worldbank_update_failure_keeps_last_good(tmp_path, monkeypatch):
    target = tmp_path / "Data.csv"
    target.write_text("last good\n")
    monkeypatch.setattr(worldbank_update, "_fetch", lambda code, timeout: [])
    result = worldbank_update.update_world_bank(target, min_country_count=1, refresh_market=False)
    assert result["status"] == "failed"
    assert target.read_text() == "last good\n"


def test_scheduler_runs_due_tasks_independently(tmp_path, monkeypatch):
    calls = []
    # The scheduler now also owns privacy/bucket/intel jobs.  This test is
    # specifically about task isolation, so keep those unrelated persistence
    # paths out of the unit test and avoid touching the developer's live DB.
    monkeypatch.setenv("PRIVACY_REFRESH_SCHEDULER", "false")
    monkeypatch.setenv("INTEL_UPDATER_ENABLED", "false")
    monkeypatch.setattr(data_scheduler, "connect", lambda: (_ for _ in ()).throw(RuntimeError("isolated")))
    monkeypatch.setattr(data_scheduler, "refresh_tor_exit_list", lambda: calls.append("tor") or {"status": "failed"})
    monkeypatch.setattr(data_scheduler, "update_world_bank", lambda: calls.append("world_bank") or {"status": "updated"})
    state = tmp_path / "update_state.json"
    result = data_scheduler.run_scheduler(state, tmp_path / "scheduler.lock", datetime.now(timezone.utc))
    assert calls == ["tor", "world_bank"]
    assert result["tasks"]["tor"]["status"] == "failed"
    assert result["tasks"]["world_bank"]["status"] == "updated"
    saved = json.loads(state.read_text())
    assert saved["world_bank"]["status"] == "updated"
