import json
import sys
import types
from datetime import datetime, timezone
from pathlib import Path

from scripts.ops import data_scheduler
from scripts.market import worldbank_update
from app.services.profiles import _claim_privacy_refresh_lease, _release_privacy_refresh_lease


def _records(code, value=1):
    return [{"countryiso3code": "USA", "country": {"value": "United States"}, "date": "2025", "value": value}]


class _LeaseResult:
    def __init__(self, row):
        self.row = row

    def fetchone(self):
        return self.row


class _LeaseConnection:
    def __init__(self, row):
        self.row = row
        self.sql = None
        self.params = None

    def execute(self, sql, params):
        self.sql = sql
        self.params = params
        return _LeaseResult(self.row)


def test_privacy_refresh_lease_claim_is_atomic_for_competing_workers():
    connection = _LeaseConnection(None)
    now = datetime(2026, 9, 12, tzinfo=timezone.utc)

    assert not _claim_privacy_refresh_lease(
        connection, "worker-b", now, now.replace(minute=5)
    )
    assert "ON CONFLICT(source_id)" in connection.sql
    assert "RETURNING lease_owner" in connection.sql
    assert "lease_expires_at <= EXCLUDED.updated_at" in connection.sql
    assert connection.params[1] == "worker-b"


def test_privacy_refresh_lease_claim_accepts_expired_takeover_and_owner_release_is_fenced():
    connection = _LeaseConnection({"lease_owner": "worker-b"})
    now = datetime(2026, 9, 12, tzinfo=timezone.utc)

    assert _claim_privacy_refresh_lease(connection, "worker-b", now, now.replace(minute=5))
    _release_privacy_refresh_lease(connection, "worker-b", now)
    assert "WHERE source_id=%s AND lease_owner=%s" in connection.sql
    assert connection.params[1:] == ("privacy-refresh", "worker-b")


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


def test_worldbank_identical_refresh_does_not_rewrite_last_good_snapshot(tmp_path, monkeypatch):
    target = tmp_path / "Data.csv"
    target.write_text("last good\n")
    monkeypatch.setattr(worldbank_update, "_fetch", lambda code, timeout: _records(code))

    first = worldbank_update.update_world_bank(target, min_country_count=1, refresh_market=False)
    last_good = (tmp_path / "Data.last-good.csv").read_bytes()
    second = worldbank_update.update_world_bank(target, min_country_count=1, refresh_market=False)

    assert first["status"] == "updated"
    assert second == {"status": "not_modified", "changed": False, "countries": 1}
    assert (tmp_path / "Data.last-good.csv").read_bytes() == last_good


def test_dev_launcher_does_not_download_geo_databases_at_startup():
    source = Path("scripts/dev_run.sh").read_text(encoding="utf-8")

    assert "SAPICS_UPDATE_ON_STARTUP" not in source
    assert "IP2REGION_UPDATE_ON_STARTUP" not in source
    assert "sapics_updater import refresh" not in source
    assert "ip2region_updater import refresh" not in source


def test_env_example_has_one_disabled_shared_intel_updater_assignment():
    source = Path(".env.example").read_text(encoding="utf-8")
    assignments = [
        line.strip()
        for line in source.splitlines()
        if line.strip().startswith("INTEL_UPDATER_ENABLED=")
    ]

    assert assignments == ["INTEL_UPDATER_ENABLED=false"]


def test_scheduler_runs_ip2region_when_due_and_skips_until_next_interval(monkeypatch):
    calls = []
    state, report = {}, {}
    now = datetime(2026, 9, 26, tzinfo=timezone.utc)
    monkeypatch.setenv("INTEL_UPDATER_ENABLED", "false")
    monkeypatch.setenv("SAPICS_UPDATER_ENABLED", "false")
    monkeypatch.setenv("IP2REGION_UPDATER_ENABLED", "true")
    monkeypatch.setenv("IP2REGION_REFRESH_HOURS", "24")
    monkeypatch.setattr(
        data_scheduler, "_refresh_ip2region",
        lambda: calls.append("ip2region") or {"status": "ok", "updated": ["v4", "v6"]},
    )

    data_scheduler._run_local_geo_database_updates(state, report, now)
    data_scheduler._run_local_geo_database_updates(state, report, now.replace(hour=23))

    assert calls == ["ip2region"]
    assert report["ip2region"]["status"] == "not_due"
    assert state["ip2region"]["last_success_at"] == now.isoformat()


def test_scheduler_uses_existing_sapics_due_source_when_intel_updater_enabled(monkeypatch):
    calls = []
    state, report = {}, {}
    monkeypatch.setenv("INTEL_UPDATER_ENABLED", "true")
    monkeypatch.setenv("SAPICS_UPDATER_ENABLED", "true")
    monkeypatch.setenv("IP2REGION_UPDATER_ENABLED", "false")
    monkeypatch.setattr(data_scheduler, "_refresh_sapics", lambda: calls.append("duplicate"))

    data_scheduler._run_local_geo_database_updates(
        state, report, datetime(2026, 9, 26, tzinfo=timezone.utc)
    )

    assert calls == []
    assert "sapics_local" not in report


def test_scheduler_runs_sapics_fallback_when_shared_intel_updater_is_disabled(monkeypatch):
    calls = []
    state, report = {}, {}
    monkeypatch.setenv("INTEL_UPDATER_ENABLED", "false")
    monkeypatch.setenv("SAPICS_UPDATER_ENABLED", "true")
    monkeypatch.setenv("IP2REGION_UPDATER_ENABLED", "false")
    monkeypatch.setattr(
        data_scheduler, "_refresh_sapics",
        lambda: calls.append("sapics") or {"status": "ok", "updated": ["country.mmdb"]},
    )

    data_scheduler._run_local_geo_database_updates(
        state, report, datetime(2026, 9, 26, tzinfo=timezone.utc)
    )

    assert calls == ["sapics"]
    assert report["sapics_local"]["status"] == "ok"


def test_ip2region_failed_validation_preserves_last_good_files(tmp_path, monkeypatch):
    from app.services import ip2region_updater

    package = types.ModuleType("ip2region")
    package.__path__ = []
    util = types.ModuleType("ip2region.util")
    util.IPv4, util.IPv6 = 4, 6
    util.verify_from_file = lambda _path: (_ for _ in ()).throw(ValueError("invalid xdb"))
    monkeypatch.setitem(sys.modules, "ip2region", package)
    monkeypatch.setitem(sys.modules, "ip2region.util", util)
    monkeypatch.setattr(ip2region_updater, "ROOT", tmp_path)
    monkeypatch.setattr(
        ip2region_updater, "urlopen",
        lambda *_args, **_kwargs: types.SimpleNamespace(read=lambda: b"invalid new xdb"),
    )
    previous = {}
    for filename in ("ip2region_v4.xdb", "ip2region_v6.xdb"):
        target = tmp_path / filename
        target.write_bytes(b"known-good database")
        previous[target] = target.read_bytes()

    result = ip2region_updater.refresh()

    assert result["status"] == "failed"
    assert all(target.read_bytes() == content for target, content in previous.items())
    assert sorted(path.name for path in tmp_path.iterdir()) == sorted(target.name for target in previous)


def test_scheduler_runs_due_tasks_independently(tmp_path, monkeypatch):
    calls = []
    # The scheduler now also owns privacy/bucket/intel jobs.  This test is
    # specifically about task isolation, so keep those unrelated persistence
    # paths out of the unit test and avoid touching the developer's live DB.
    for variable in (
        "COMTRADE_MIRROR_REFRESH", "GEOGRAPHY_REFRESH", "OSM_REFRESH",
        "OSM_AUXILIARY_REFRESH", "LOCAL_OPPORTUNITY_REFRESH",
        "AREA_MEMBERSHIP_REFRESH", "LOCAL_OVERLAP_REFRESH",
    ):
        monkeypatch.setenv(variable, "false")
    monkeypatch.setenv("PRIVACY_REFRESH_SCHEDULER", "false")
    monkeypatch.setenv("INTEL_UPDATER_ENABLED", "false")
    monkeypatch.setenv("COUNTRY_DEMAND_REFRESH", "false")
    monkeypatch.setenv("MARKET_SOURCES_REFRESH", "false")
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


def test_scheduler_osm_is_explicit_and_reported(tmp_path, monkeypatch):
    monkeypatch.setenv("OSM_REFRESH", "true")
    monkeypatch.setenv("GEOGRAPHY_REFRESH", "false")
    monkeypatch.setenv("COMTRADE_MIRROR_REFRESH", "false")
    monkeypatch.setenv("MARKET_SOURCES_REFRESH", "false")
    monkeypatch.setenv("PRIVACY_REFRESH_SCHEDULER", "false")
    monkeypatch.setenv("INTEL_UPDATER_ENABLED", "false")
    monkeypatch.setenv("COUNTRY_DEMAND_REFRESH", "false")
    monkeypatch.setattr(data_scheduler, "refresh_tor_exit_list", lambda: {"status": "not_modified"})
    monkeypatch.setattr(data_scheduler, "update_world_bank", lambda: {"status": "not_modified"})
    monkeypatch.setattr(data_scheduler, "refresh_osm_pilot", lambda repo: {"status": "completed", "countries": {"SG": {"status": "skipped_unchanged"}}})
    result = data_scheduler.run_scheduler(tmp_path / "state.json", tmp_path / "lock", datetime.now(timezone.utc))
    assert result["tasks"]["osm"]["status"] == "completed"


def test_scheduler_auxiliary_is_explicit_and_reported(tmp_path, monkeypatch):
    monkeypatch.setenv("OSM_AUXILIARY_REFRESH", "true")
    monkeypatch.setenv("OSM_REFRESH", "false")
    monkeypatch.setenv("GEOGRAPHY_REFRESH", "false")
    monkeypatch.setenv("COMTRADE_MIRROR_REFRESH", "false")
    monkeypatch.setenv("MARKET_SOURCES_REFRESH", "false")
    monkeypatch.setenv("PRIVACY_REFRESH_SCHEDULER", "false")
    monkeypatch.setenv("INTEL_UPDATER_ENABLED", "false")
    monkeypatch.setenv("COUNTRY_DEMAND_REFRESH", "false")
    monkeypatch.setattr(data_scheduler, "refresh_tor_exit_list", lambda: {"status": "not_modified"})
    monkeypatch.setattr(data_scheduler, "update_world_bank", lambda: {"status": "not_modified"})
    monkeypatch.setattr(data_scheduler, "refresh_local_evidence", lambda repo: {"status": "completed", "countries": {"DE": {"status": "updated"}}})
    result = data_scheduler.run_scheduler(tmp_path / "state.json", tmp_path / "lock", datetime.now(timezone.utc))
    assert result["tasks"]["osm_auxiliary"]["status"] == "completed"


def test_scheduler_market_sources_runs_source_refresh_and_prior(tmp_path, monkeypatch):
    for variable in ("GEOGRAPHY_REFRESH", "COMTRADE_MIRROR_REFRESH", "OSM_REFRESH", "OSM_AUXILIARY_REFRESH"):
        monkeypatch.setenv(variable, "false")
    monkeypatch.setenv("MARKET_SOURCES_REFRESH", "true")
    monkeypatch.setenv("PRIVACY_REFRESH_SCHEDULER", "false")
    monkeypatch.setenv("INTEL_UPDATER_ENABLED", "false")
    monkeypatch.setenv("COUNTRY_DEMAND_REFRESH", "false")
    monkeypatch.setattr(data_scheduler, "refresh_tor_exit_list", lambda: {"status": "not_modified"})
    monkeypatch.setattr(data_scheduler, "update_world_bank", lambda: {"status": "not_modified"})
    monkeypatch.setattr(data_scheduler, "refresh_country_sources", lambda path, now: {"status": "updated", "sources": {}})
    monkeypatch.setattr(data_scheduler, "refresh_country_prior", lambda: {"status": "updated", "rows": 3})
    result = data_scheduler.run_scheduler(tmp_path / "state.json", tmp_path / "lock", datetime.now(timezone.utc))
    assert result["tasks"]["market_sources"]["status"] == "updated"
    assert result["tasks"]["market_sources"]["country_prior"]["rows"] == 3
