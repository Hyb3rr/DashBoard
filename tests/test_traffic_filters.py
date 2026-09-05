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
