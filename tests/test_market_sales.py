from pathlib import Path
from collections import Counter

from scripts.import_rfq_csv import validate_rows
from scripts.market.fx_rates import ExchangeRateHostClient


def _row(**overrides):
    row = {
        "geo_unit_id": "VN-BD", "product_id": "cnc_router", "customer_name": "Acme",
        "stage": "won", "created_at": "2026-09-01T00:00:00Z", "deal_value_original": "1000",
        "deal_value_currency": "USD", "fx_rate_used": "1", "fx_rate_date": "2026-09-01",
    }
    row.update(overrides)
    return row


def test_csv_validation_never_infers_geo_or_product():
    accepted, rejected = validate_rows([_row(geo_unit_id="unknown")], {"VN-BD"}, {"cnc_router"})
    assert accepted == []
    assert rejected == Counter({"missing_geo": 1})


def test_csv_validation_rejects_negative_values_and_invalid_stage():
    accepted, rejected = validate_rows([_row(deal_value_original="-1"), _row(stage="closed")], {"VN-BD"}, {"cnc_router"})
    assert accepted == []
    assert rejected == Counter({"invalid_value_or_fx": 1, "invalid_stage": 1})


def test_csv_validation_derives_fx_date_and_identity_usd_rate():
    accepted, rejected = validate_rows([_row(fx_rate_used="", fx_rate_date="", quoted_at="2026-09-02T10:00:00Z")], {"VN-BD"}, {"cnc_router"})
    assert not rejected
    assert accepted[0]["fx_rate_used"] == "1"
    assert accepted[0]["fx_rate_provider"] == "identity_usd"
    assert accepted[0]["fx_rate_date"] == "2026-09-02"


def test_csv_validation_rejects_non_usd_without_rate_provider():
    accepted, rejected = validate_rows([_row(deal_value_currency="VND", fx_rate_used="25000", fx_rate_date="2026-09-01")], {"VN-BD"}, {"cnc_router"})
    assert accepted == []
    assert rejected == Counter({"missing_fx_rate": 1})


def test_csv_validation_can_resolve_missing_historical_fx_without_guessing():
    calls = []
    def resolver(currency, date):
        calls.append((currency, date))
        return "0.00004"
    accepted, rejected = validate_rows(
        [_row(deal_value_currency="VND", fx_rate_used="", fx_rate_provider="", fx_rate_date="")],
        {"VN-BD"}, {"cnc_router"}, resolver,
    )
    assert not rejected
    assert accepted[0]["fx_rate_used"] == "0.00004"
    assert accepted[0]["fx_rate_provider"] == "exchangerate.host"
    assert calls == [("VND", "2026-09-01")]


def test_fx_client_caches_currency_date(monkeypatch):
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): return False
    calls = []
    def fake_open(request, timeout):
        calls.append(request.full_url)
        return Response()
    monkeypatch.setattr("scripts.market.fx_rates.urlopen", fake_open)
    monkeypatch.setattr("scripts.market.fx_rates.json.load", lambda response: {"success": True, "rates": {"USD": "0.00004"}})
    client = ExchangeRateHostClient("test-key", "https://example.test/historical")
    assert client.get_rate("VND", "2026-09-01") == client.get_rate("VND", "2026-09-01")
    assert len(calls) == 1


def test_contract_has_fx_audit_fields_and_no_summary_write():
    sql = Path("infra/postgres/022_market_sales_intake.sql").read_text()
    fx_sql = Path("infra/postgres/023_market_sales_fx_audit.sql").read_text()
    assert "deal_value_original" in sql
    assert "deal_value_currency" in sql
    assert "fx_rate_used" in sql
    assert "fx_rate_date" in sql
    assert "fx_rate_provider" in fx_sql
    assert "rfq_deal_value_non_negative" in sql
    assert "market_city_product_summary" not in sql


def test_contract_uses_sql_view_as_aggregation_source():
    sql = Path("infra/postgres/022_market_sales_intake.sql").read_text()
    assert "CREATE OR REPLACE VIEW rfq_summary_by_geo_product" in sql
    assert "win_rate" in sql
    assert "avg_deal_value_usd" in sql
