"""PostgreSQL pool lifecycle tests without requiring a live database."""

import pytest

from app.db import postgres


class _FakePool:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.closed = False
        self.open_calls: list[tuple[bool, float]] = []
        self.close_calls: list[float] = []

    def open(self, *, wait: bool, timeout: float) -> None:
        self.open_calls.append((wait, timeout))
        if self.error:
            raise self.error

    def close(self, *, timeout: float = 5.0) -> None:
        self.close_calls.append(timeout)
        self.closed = True


def _install_pool_factory(monkeypatch, pools: list[_FakePool]) -> None:
    def factory():
        pool = pools.pop(0)
        postgres._pool = pool
        postgres._pool_dsn = "test-dsn"
        return pool

    monkeypatch.setattr(postgres, "_connection_pool", factory)
    postgres._pool = None
    postgres._pool_dsn = None
    postgres._pool_open = False


def test_failed_open_discards_terminal_pool_and_next_attempt_recovers(monkeypatch):
    monkeypatch.setenv("POSTGRES_DSN", "test-dsn")
    monkeypatch.setenv("POSTGRES_POOL_OPEN_TIMEOUT_SECONDS", "0.25")
    failed = _FakePool(RuntimeError("database unavailable"))
    recovered = _FakePool()
    _install_pool_factory(monkeypatch, [failed, recovered])

    with pytest.raises(RuntimeError, match="database unavailable"):
        postgres.open_pool()

    assert failed.closed
    assert failed.close_calls == [1.0]
    assert postgres._pool is None
    assert postgres._pool_dsn is None
    assert not postgres._pool_open

    assert postgres.open_pool() is recovered
    assert recovered.open_calls == [(True, 0.25)]
    assert postgres._pool_open


def test_invalid_open_timeout_uses_safe_default(monkeypatch):
    monkeypatch.setenv("POSTGRES_DSN", "test-dsn")
    monkeypatch.setenv("POSTGRES_POOL_OPEN_TIMEOUT_SECONDS", "invalid")
    pool = _FakePool()
    _install_pool_factory(monkeypatch, [pool])

    postgres.open_pool()

    assert pool.open_calls == [(True, 5.0)]
