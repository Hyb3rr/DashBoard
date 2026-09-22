from contextlib import contextmanager

from app.routers import traffic


class _Result:
    def fetchall(self):
        return [{"ip": "203.0.113.10"}, {"ip": "203.0.113.11"}]


class _Connection:
    def execute(self, *_args):
        return _Result()


def test_country_filter_loads_ips_for_include_and_exclude(monkeypatch):
    @contextmanager
    def transaction():
        yield _Connection()

    monkeypatch.setattr(traffic.postgres_store, "transaction", transaction)

    expected = ["203.0.113.10", "203.0.113.11"]
    assert traffic._country_ips("us", False) == expected
    assert traffic._country_ips("us", True) == expected


def test_clickhouse_filter_receives_already_resolved_cohort(monkeypatch):
    from datetime import datetime, timezone
    from app.db import clickhouse

    class Client:
        def __init__(self):
            self.queries = []

        def query(self, sql, parameters=None):
            self.queries.append((sql, parameters))
            class Result:
                column_names = []
                result_rows = []
            return Result()

        def close(self):
            pass

    client = Client()
    monkeypatch.setattr(clickhouse, "connect", lambda: client)
    now = datetime.now(timezone.utc)
    clickhouse.traffic(now, now, 60, filter_type="classification", filter_value="low",
                       exclude=True, allowed_ips=["203.0.113.8"])
    assert client.queries
    assert all("src_ip IN {allowed_ips:Array(IPv6)}" in sql for sql, _ in client.queries)
