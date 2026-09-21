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

    def execute(self, sql, params):
        self.sql.append(sql)
        self.params.append(params)
        return _Result(next(self.rowcounts))

    def commit(self):
        self.commits += 1


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


def test_scheduler_retention_failure_is_isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("RETENTION_CLEANUP_ENABLED", "true")
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
