import json
import os
from datetime import datetime, timedelta, timezone
from urllib.error import HTTPError
from urllib.request import Request
from pathlib import Path
import pytest

from app.core.regions import normalise_economic_indicators
from scripts.market import market_refresh
from scripts.market import comtrade_update


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


def test_trade_score_falls_back_two_years_and_marks_lagging():
    indicators = {"AA": {name: {"value": 100} for name in market_refresh.WB_CODES}}
    trade = {"AA": {"8465": {2023: 100}}}
    result = market_refresh._build_market(indicators, trade)["AA"]
    assert result["market_score"] is not None
    assert result["trade_data_year"] == 2023
    assert result["trade_data_age_years"] == 2
    assert result["trade_freshness"] == "lagging"
    assert result["score_status"] == "scored_with_fallback_year"


def test_trade_older_than_freshness_window_is_not_scored():
    indicators = {"AA": {name: {"value": 100} for name in market_refresh.WB_CODES}}
    trade = {"AA": {"8465": {2022: 100}}}
    result = market_refresh._build_market(indicators, trade)["AA"]
    assert result["market_score"] is None
    assert result["trade_data_year"] == 2022
    assert result["trade_freshness"] == "stale"
    assert result["score_status"] == "insufficient_trade_data"


def test_descendants_are_aggregated_when_parent_is_missing():
    indicators = {"AA": {name: {"value": 100} for name in market_refresh.WB_CODES}}
    trade = {"AA": {"846510": {2025: 40}, "846520": {2025: 60}}}
    result = market_refresh._build_market(indicators, trade)["AA"]
    assert result["trade_data_method"] == "reporter_hs_children"
    assert result["trade_data_year"] == 2025
    assert result["machine_demand"] is not None


def test_parent_wins_over_descendants_without_double_counting():
    trade = {"AA": {"8465": {2025: 100}, "846510": {2025: 900}, "846520": {2025: 900}}}
    score = market_refresh._trade_scores(trade)["AA"]
    assert score["trade_data_method"] == "reporter_parent"
    assert score["series"] == [{"year": 2025, "value": 100}]


def test_mirror_provenance_is_preserved_in_score_status():
    indicators = {"AA": {name: {"value": 100} for name in market_refresh.WB_CODES}}
    trade = {"AA": {"8465": {2025: 100}}}
    result = market_refresh._build_market(indicators, trade, {"AA": "mirror"})["AA"]
    assert result["trade_data_method"] == "mirror"
    assert result["score_status"] == "scored_with_mirror"


def test_mirror_refresh_preserves_previous_good_state_on_partial_failure(tmp_path):
    path = tmp_path / "mirror.json"
    calls = {"n": 0}

    def fetcher(country, year):
        calls["n"] += 1
        if calls["n"] == 1:
            return [{"partnerISO": country, "primaryValue": 123}]
        raise RuntimeError("temporary API failure")

    first = comtrade_update.refresh(["AA"], [2025], fetcher, path)
    payload = json.loads(path.read_text())
    second = comtrade_update.refresh(["AA"], [2025], fetcher, path, now=datetime.now(timezone.utc) + timedelta(hours=25))
    assert first["observations"] == 1
    assert second["failed"] == 1
    assert json.loads(path.read_text())["trade"] == payload["trade"]


def test_mirror_refresh_is_idempotent_for_same_observation(tmp_path):
    path = tmp_path / "mirror.json"
    fetcher = lambda country, year: [{"partnerISO": country, "primaryValue": 123}]
    comtrade_update.refresh(["AA"], [2025], fetcher, path)
    first = json.loads(path.read_text())["trade"]
    comtrade_update.refresh(["AA"], [2025], fetcher, path)
    assert json.loads(path.read_text())["trade"] == first


def test_recent_mirror_wins_when_reporter_is_stale():
    indicators = {"AA": {name: {"value": 100} for name in market_refresh.WB_CODES}}
    trade = {"AA": {"8465": {2022: 10, 2025: 80}}}
    provenance = {"AA": {"method": "mirror", "confidence": "medium", "years": ["2025"], "reporter_parent_years": [2022], "reporter_child_years": {}}}
    result = market_refresh._build_market(indicators, trade, provenance)["AA"]
    assert result["trade_data_method"] == "mirror"
    assert result["trade_confidence"] == "medium"


def test_bilateral_mirror_rows_are_deduplicated():
    rows = [
        {"reporterCode": 276, "partnerCode": 0, "refYear": 2025, "mirrorPrimaryValue": 12},
        {"reporterCode": 276, "partnerCode": 0, "refYear": 2025, "mirrorPrimaryValue": 12},
    ]
    assert comtrade_update._aggregate(rows, "DE", 2025) == 12


def test_rate_limit_retries_with_bounded_backoff(monkeypatch):
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): return None
        def read(self): return b'{"data": []}'

    attempts = {"n": 0}
    delays = []
    def opener(request, timeout):
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise HTTPError(request.full_url, 429, "limited", {"Retry-After": "2"}, None)
        return Response()
    result = comtrade_update._request_json(Request("https://example.test"), opener=opener, sleep_fn=delays.append, max_attempts=3)
    assert result == {"data": []}
    assert attempts["n"] == 3
    assert delays == [2.0, 2.0]


def test_no_trade_and_no_mirror_remains_null():
    indicators = {"AA": {name: {"value": 100} for name in market_refresh.WB_CODES}}
    result = market_refresh._build_market(indicators, {})["AA"]
    assert result["market_score"] is None
    assert result["missing_reason"] == "insufficient_trade_data"
