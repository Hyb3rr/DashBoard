from app.core import intel_updater


class _Result:
    def fetchone(self):
        return {"acquired": False}


class _Connection:
    def __init__(self):
        self.closed = False
        self.commits = 0
        self.rollbacks = 0
        self.executed = []

    def execute(self, *args):
        self.executed.append(args)
        return _Result()

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closed = True


def test_intel_refresh_skips_when_database_lock_is_held(monkeypatch):
    connection = _Connection()
    monkeypatch.setattr(intel_updater.postgres, "connect", lambda: connection)

    result = intel_updater.run_due_sources()

    assert result == {"status": "locked", "backend": "postgres"}
    assert connection.closed is True


def test_provider_exception_persists_failure_status_in_separate_transaction(monkeypatch):
    provider_conn = _Connection()
    status_conn = _Connection()
    connections = iter((provider_conn, status_conn))
    monkeypatch.setattr(intel_updater.postgres, "connect", lambda: next(connections))

    result = intel_updater._run_provider_pg(
        lambda _conn: (_ for _ in ()).throw(TimeoutError("provider timeout")),
        "test_source",
        None,
    )

    assert result["status"] == "failed"
    assert provider_conn.rollbacks == 1
    assert provider_conn.commits == 0
    assert status_conn.commits == 1
    assert any("intel_source_status" in args[0] for args in status_conn.executed)
    assert provider_conn.closed is True
    assert status_conn.closed is True


def test_failure_status_write_does_not_mask_provider_exception(monkeypatch):
    provider_conn = _Connection()
    status_conn = _Connection()
    status_conn.execute = lambda *_args: (_ for _ in ()).throw(RuntimeError("status db down"))
    connections = iter((provider_conn, status_conn))
    monkeypatch.setattr(intel_updater.postgres, "connect", lambda: next(connections))

    result = intel_updater._run_provider_pg(
        lambda _conn: (_ for _ in ()).throw(ValueError("bad payload")),
        "test_source",
        None,
    )

    assert result == {"status": "failed", "error": "ValueError: bad payload", "records_upserted": 0}
    assert provider_conn.closed is True
    assert status_conn.rollbacks == 1
    assert status_conn.closed is True


def test_provider_success_status_behavior_is_unchanged(monkeypatch):
    connection = _Connection()
    monkeypatch.setattr(intel_updater.postgres, "connect", lambda: connection)

    result = intel_updater._run_provider_pg(
        lambda _conn: {"status": "updated", "records_upserted": 3},
        "test_source",
        None,
    )

    assert result == {"status": "updated", "records_upserted": 3}
    assert connection.commits == 1
    assert connection.rollbacks == 0
    assert any("intel_source_status" in args[0] for args in connection.executed)
