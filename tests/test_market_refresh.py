import json
import os
from pathlib import Path
import pytest

from app.core.regions import normalise_economic_indicators
from app.tools import market_refresh


def test_legacy_economic_indicators_normalise_to_object():
    value = normalise_economic_indicators([{"label": "GDP", "value": 10}])
    assert value["indicators"]["gdp"]["value"] == 10


def test_world_bank_metadata_parser_reads_composite_export():
    metadata = market_refresh.parse_world_bank_metadata()
    assert "NY.GDP.MKTP.CD" in metadata


def test_comtrade_parser_discovers_existing_years_and_parent():
    trade, diagnostics = market_refresh.parse_comtrade()
    assert diagnostics["latest_complete_year"] == 2025
    assert 2025 in diagnostics["years"]
    assert any("8465" in country_data for country_data in trade.values())


@pytest.mark.integration
def test_seed_cache_skips_unchanged_file():
    pytest.skip("Requires PostgreSQL RegionRepository")


def test_refresh_atomic_failure_keeps_live_seed(tmp_path, monkeypatch):
    seed = tmp_path / "seed.json"
    original = [{"country_code": "US", "country_name": "United States"}]
    seed.write_text(json.dumps(original))
    monkeypatch.setattr(market_refresh, "WB_DATA", tmp_path / "missing.csv")
    monkeypatch.setattr(market_refresh, "WB_METADATA", tmp_path / "missing-meta.csv")
    try:
        market_refresh.refresh(seed)
    except FileNotFoundError:
        pass
    assert json.loads(seed.read_text()) == original
    assert not list(tmp_path.glob(".seed.json.*.tmp"))


def test_revised_score_blends_economic_and_machine_demand():
    indicators = {}
    for index, country in enumerate(("AA", "BB"), start=1):
        indicators[country] = {
            "gdp_current_usd": {"value": index * 100},
            "gdp_per_capita": {"value": index * 100},
            "gdp_growth": {"value": index},
            "population": {"value": index * 100},
            "manufacturing_value_added": {"value": index * 100},
            "manufacturing_share": {"value": index},
            "manufacturing_growth": {"value": index},
            "industry_value_added": {"value": index * 100},
            "industry_share": {"value": index},
            "forest_area": {"value": index * 100},
            "forest_share": {"value": index},
            "merchandise_imports": {"value": index * 100},
        }
    trade = {}
    for index, country in enumerate(("AA", "BB"), start=1):
        trade[country] = {"8465": {year: index * 100 for year in range(2021, 2026)}}
        trade[country].update({hs: {2025: index * 10} for hs in market_refresh.HS_SUB})

    result = market_refresh._build_market(indicators, trade)
    for item in result.values():
        components = item["market_components"]
        assert item["economic_potential"] == components["economic_potential"]
        assert item["machine_demand"] == components["product_demand"]
        assert item["market_score"] == round(
            components["economic_potential"] * 0.4 + components["machine_demand"] * 0.6, 2
        )
