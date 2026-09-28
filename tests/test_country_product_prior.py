from pathlib import Path
import json

from app.core.market_potential import country_prior_snapshot, minmax_normalize
from scripts.market.country_product_prior import build_prior_rows, read_trade


def test_minmax_normalization_preserves_missing_values():
    result = minmax_normalize({"VN": 10, "ID": 20, "TH": None})
    assert result == {"VN": 0.0, "ID": 1.0, "TH": None}


def test_country_prior_is_null_when_fewer_than_three_signals_exist():
    result = country_prior_snapshot({"hs_import": 1.0, "manufacturing_growth": 0.5}, "woodworking")
    assert result["score"] is None
    assert result["data_coverage"] == 0.3333


def test_build_prior_is_product_specific_and_does_not_fake_missing_signals():
    rows = build_prior_rows(
        {"VN": {"manufacturing_value_added": 100, "manufacturing_growth": 2}},
        {"VN": {"846520": 1000}, "ID": {"846520": 2000}},
        [{"product_id": "cnc_router", "category": "woodworking", "hs_codes": ["846520"]}],
    )
    assert len(rows) == 2
    assert {row["product_id"] for row in rows} == {"cnc_router"}
    assert all(row["country_product_prior"] is None for row in rows)
    assert all(row["signal_values"]["sector_consumption"] is None for row in rows)


def test_furniture_exports_and_external_country_signals_are_inputs():
    rows = build_prior_rows(
        {"VN": {"manufacturing_value_added": 100, "manufacturing_growth": 2}},
        {"VN": {"846520": 1000}},
        [{"product_id": "cnc_router", "category": "woodworking", "hs_codes": ["846520"]}],
        {"VN": {"940330": 500}},
        {"labor_cost_pressure": {"VN": 0.5}, "cement_consumption": {"VN": 0.7}},
    )
    assert rows[0]["signal_values"]["relevant_export"] == 1.0
    assert rows[0]["signal_values"]["labor_cost_pressure"] == 0.5


def test_country_prior_phase_does_not_write_summary_table():
    sql = Path("scripts/market/country_product_prior.py").read_text()
    assert "market_city_product_summary" not in sql


def test_trade_reader_keeps_latest_annual_values_and_merges_latest_furniture_mirror(tmp_path):
    (tmp_path / "trade.csv").write_text(
        "freqCode,flowCode,partnerISO,reporterISO,cmdCode,refYear,primaryValue\n"
        "A,X,W00,VNM,940330,2022,10\n"
        "A,X,W00,VNM,940330,2024,12\n"
        "M,X,W00,VNM,940330,2025,99\n",
        encoding="utf-8",
    )
    (tmp_path / "mirror.json").write_text(
        json.dumps({"trade": {"VN": {"9403": {"2023": 13, "2025": 17}}}}),
        encoding="utf-8",
    )

    result = read_trade(tmp_path, flow_code="X")

    assert result["VN"]["940330"] == 12
    assert result["VN"]["9403"] == 17
