from datetime import datetime, timezone

from app.services import retention_cleanup


class _Result:
    def __init__(self, rowcount):
        self.rowcount = rowcount


class _Connection:
    def __init__(self, rowcounts):
        self.rowcounts = iter(rowcounts)
        self.sql = []
        self.params = []
        self.commits = 0
        self.closed = False
        self.rollbacks = 0

    def execute(self, sql, params):
        self.sql.append(sql)
        self.params.append(params)
        return _Result(next(self.rowcounts))

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closed = True


def test_cleanup_preserves_new_rows_and_deletes_only_bounded_old_chunks():
    connection = _Connection([2, 0, 1, 0])
    result = retention_cleanup.cleanup_derived_state(
        connection,
        now=datetime(2026, 9, 18, tzinfo=timezone.utc),
        retention_days=37,
        max_rows=3,
        chunk_size=2,
        max_seconds=5,
    )

    assert result["total_deleted"] == 3
    assert result["deleted"] == {"ip_minute_features": 2, "ip_minute_path_seen": 1}
    assert result["retention_days"] == 37
    assert connection.commits == 3
    assert all("bucket_minute < %s" in sql for sql in connection.sql)
    assert all(params[0].isoformat().startswith("2026-08-12") for params in connection.params)


def test_cleanup_is_disabled_without_explicit_enable(monkeypatch):
    monkeypatch.delenv("RETENTION_CLEANUP_ENABLED", raising=False)
    assert retention_cleanup.run_once()["status"] == "disabled"


def test_change_log_retention_uses_maintenance_connection(monkeypatch):
    connection = _Connection([7])
    monkeypatch.setattr(retention_cleanup.postgres, "connect", lambda: connection)

    result = retention_cleanup.run_change_log_retention()

    assert result == {"status": "completed", "deleted": 7}
    assert "DELETE FROM ip_change_log" in connection.sql[0]
    assert connection.commits == 1
    assert connection.closed


def test_scheduler_runs_change_log_retention_without_ai_or_general_retention(monkeypatch):
    from scripts.ops import data_scheduler

    monkeypatch.delenv("CHANGE_LOG_RETENTION_ENABLED", raising=False)
    for name in (
        "PRIVACY_REFRESH_SCHEDULER", "INTEL_UPDATER_ENABLED",
        "RETENTION_CLEANUP_ENABLED",
    ):
        monkeypatch.setenv(name, "false")
    calls = []
    monkeypatch.setattr(
        data_scheduler, "run_change_log_retention",
        lambda: calls.append("trim") or {"status": "completed", "deleted": 0},
    )

    report = {}
    data_scheduler._run_background_jobs(report, datetime(2026, 9, 18, tzinfo=timezone.utc))

    assert calls == ["trim"]
    assert report["change_log_retention"]["status"] == "completed"
    assert "retention" not in report


def test_privacy_change_history_cleanup_is_bounded_and_separate_from_legacy():
    connection = _Connection([2, 0])
    result = retention_cleanup.cleanup_privacy_change_history(
        connection,
        now=datetime(2026, 9, 18, tzinfo=timezone.utc),
        retention_days=180,
        max_rows=3,
        chunk_size=2,
        max_seconds=5,
    )

    assert result["table"] == "privacy_network_change_history"
    assert result["deleted"] == 2
    assert connection.commits == 2
    assert all("changed_at < %s" in sql for sql in connection.sql)
    assert all("privacy_network_history" not in sql for sql in connection.sql)


def test_scheduler_retention_failure_is_isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("RETENTION_CLEANUP_ENABLED", "true")
    monkeypatch.setenv("CHANGE_LOG_RETENTION_ENABLED", "false")
    monkeypatch.setattr(retention_cleanup, "run_once", lambda now: (_ for _ in ()).throw(RuntimeError("cleanup unavailable")))
    monkeypatch.setenv("PRIVACY_REFRESH_SCHEDULER", "false")
    monkeypatch.setenv("INTEL_UPDATER_ENABLED", "false")
    monkeypatch.setenv("COUNTRY_DEMAND_REFRESH", "false")
    monkeypatch.setenv("OSM_REFRESH", "false")
    monkeypatch.setenv("OSM_AUXILIARY_REFRESH", "false")
    monkeypatch.setenv("COMTRADE_MIRROR_REFRESH", "false")
    monkeypatch.setenv("MARKET_SOURCES_REFRESH", "false")
    monkeypatch.setenv("GEOGRAPHY_REFRESH", "false")
    monkeypatch.setenv("LOCAL_OPPORTUNITY_REFRESH", "false")
    monkeypatch.setenv("AREA_MEMBERSHIP_REFRESH", "false")
    monkeypatch.setenv("LOCAL_OVERLAP_REFRESH", "false")
    result = __import__("scripts.ops.data_scheduler", fromlist=["run_scheduler"]).run_scheduler(
        tmp_path / "state.json", tmp_path / "lock", datetime(2026, 9, 18, tzinfo=timezone.utc)
    )
    assert result["tasks"]["retention"]["status"] == "failed"
