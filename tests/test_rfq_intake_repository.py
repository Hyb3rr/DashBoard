from contextlib import contextmanager

import app.db.market_repository as market_repository
import app.db.market_demand_repository as market_demand_repository


def test_rfq_value_mapping_preserves_order_and_defaults():
    """Keep normalized RFQ values aligned with the UPSERT column order."""
    values = market_demand_repository._rfq_values({
        "geo_unit_id": "VN-01",
        "product_id": "woodworking",
        "customer_name": "Example buyer",
        "stage": "new",
        "is_repeat_customer": "YES",
    })

    assert len(values) == 21
    assert values[:6] == (None, "VN-01", "woodworking", "Example buyer", None, "new")
    assert values[14:19] == (True, None, None, "manual_csv", None)


def test_rfq_upsert_uses_stable_source_identity_and_reports_rows(monkeypatch):
    """Persist one batch with its source identity conflict contract unchanged."""
    captured = {}

    @contextmanager
    def transaction():
        """Provide a fake transaction scope for the repository contract test."""
        yield object()

    def record_batch(_connection, sql, values):
        """Capture the statement and normalized batch supplied by the repository."""
        captured["sql"] = sql
        captured["values"] = values

    monkeypatch.setattr(market_demand_repository, "transaction", transaction)
    monkeypatch.setattr(market_demand_repository, "_executemany", record_batch)

    count = market_repository.MarketRepository().upsert_rfq_intake([{
        "geo_unit_id": "VN-01", "product_id": "woodworking",
        "customer_name": "Example buyer", "stage": "new",
        "source_system": "crm", "source_record_id": "crm-42",
    }])

    assert count == 1
    assert "ON CONFLICT (source_system,source_record_id)" in captured["sql"]
    assert captured["values"][0][17:19] == ("crm", "crm-42")
