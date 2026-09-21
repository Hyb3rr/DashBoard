import inspect
import json
from uuid import uuid4

from app.db import market_repository


def test_latest_evidence_can_be_pinned_to_published_snapshot():
    source = inspect.getsource(market_repository.MarketRepository.list_latest_industrial_demand_evidence)
    assert "e.snapshot_id=%s::uuid" in source


class Result:
    rowcount = 1

    def fetchall(self):
        return []


class Connection:
    def __init__(self):
        self.calls = []
        self.batches = []

    def execute(self, sql, params=()):
        self.calls.append((sql, params))
        return Result()

    def cursor(self):
        return self

    def executemany(self, sql, values):
        self.batches.append((sql, list(values)))

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class Tx:
    def __init__(self, conn):
        self.conn = conn

    def __enter__(self):
        return self.conn

    def __exit__(self, *exc):
        return False


def test_snapshot_creation_is_retry_safe(monkeypatch):
    conn = Connection()
    monkeypatch.setattr(market_repository, "transaction", lambda: Tx(conn))
    snapshot_id = str(uuid4())
    repo = market_repository.MarketRepository()
    assert repo.create_industrial_demand_snapshot({
        "snapshot_id": snapshot_id, "country_code": "VN", "model_version": "market-demand-v2",
        "product_count": 14,
    }) == snapshot_id
    assert "ON CONFLICT (snapshot_id) DO NOTHING" in conn.calls[0][0]


def test_evidence_upsert_is_batch_and_preserves_null(monkeypatch):
    conn = Connection()
    monkeypatch.setattr(market_repository, "transaction", lambda: Tx(conn))
    repo = market_repository.MarketRepository()
    count = repo.upsert_industrial_demand_evidence([{
        "snapshot_id": str(uuid4()), "evidence_id": "demand_1", "country_code": "VN",
        "geo_unit_id": "VN:ADM1:BD", "product_id": "panel_saw", "source_id": "osm_overpass",
        "source_geo_scope": "geo_unit", "observed_value": None, "unit": "observed_entities",
        "observed_period": "2026-Q3", "collected_at": "2026-09-09T00:00:00Z",
        "mapping_version": "market-demand-v2", "limitations": ["partial coverage"],
    }])
    assert count == 1
    sql, values = conn.batches[0]
    assert "ON CONFLICT (snapshot_id,evidence_id)" in sql
    assert values[0][7] is None
    assert json.loads(values[0][12]) == ["partial coverage"]


def test_publish_only_transitions_pending(monkeypatch):
    conn = Connection()
    monkeypatch.setattr(market_repository, "transaction", lambda: Tx(conn))
    assert market_repository.MarketRepository().publish_industrial_demand_snapshot(str(uuid4()), 3)
    sql, params = conn.calls[0]
    assert "status='pending'" in sql
    assert params[0] == 3
