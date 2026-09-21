from pathlib import Path

import json

from scripts.market import country_sources
from scripts.market.country_sources import read_normalized_signal


def test_normalized_source_reader_uses_latest_year_and_iso2(tmp_path: Path):
    path = tmp_path / "signal.csv"
    path.write_text("country_code,year,value\nVNM,2023,10\nVN,2024,20\nIDN,2024,30\n", encoding="utf-8")
    assert read_normalized_signal(path, ("value",)) == {"VN": 20.0, "ID": 30.0}


def test_faostat_json_is_normalized_and_keeps_latest_year(tmp_path, monkeypatch):
    payload = {"data": [
        {"Area Code (M49)": "704", "Year": "2022", "Value": "10"},
        {"Area Code (M49)": "704", "Year": "2023", "Value": "12"},
        {"Area Code (M49)": "360", "Year": "2023", "Value": "8"},
    ]}
    monkeypatch.setattr(country_sources, "_request_bytes", lambda *args, **kwargs: json.dumps(payload).encode())
    result = country_sources.refresh_faostat(tmp_path / "fao.csv", url="https://example.test/fao")
    assert result["status"] == "updated"
    assert read_normalized_signal(tmp_path / "fao.csv", ("value",)) == {"VN": 12.0, "ID": 8.0}


def test_ilostat_sdmx_json_is_normalized(tmp_path, monkeypatch):
    payload = {
        "structure": {"dimensions": {"observation": [
            {"id": "REF_AREA", "values": [{"id": "DE"}]},
            {"id": "TIME_PERIOD", "values": [{"id": "2024"}]},
        ]}},
        "dataSets": [{"observations": {"0:0": [321.5]}}],
    }
    monkeypatch.setattr(country_sources, "_request_bytes", lambda *args, **kwargs: json.dumps(payload).encode())
    result = country_sources.refresh_ilostat(tmp_path / "ilo.csv", url="https://example.test/ilo")
    assert result["status"] == "updated"
    assert read_normalized_signal(tmp_path / "ilo.csv", ("value",)) == {"DE": 321.5}


def test_ilostat_nested_series_selects_total_usd(tmp_path, monkeypatch):
    payload = {
        "data": {
            "structures": [{"dimensions": {
                "series": [
                    {"id": "REF_AREA", "values": [{"id": "VN"}]},
                    {"id": "SEX", "values": [{"id": "SEX_T"}, {"id": "SEX_M"}]},
                    {"id": "CUR", "values": [{"id": "CUR_TYPE_USD"}, {"id": "CUR_TYPE_LCU"}]},
                ],
                "observation": [{"id": "TIME_PERIOD", "values": [{"id": "2024"}] }],
            }}],
            "dataSets": [{"structure": 0, "series": {
                "0:0:0": {"observations": {"0": [100.0]}},
                "0:1:0": {"observations": {"0": [90.0]}},
                "0:0:1": {"observations": {"0": [2500.0]}},
            }}],
        }
    }
    monkeypatch.setattr(country_sources, "_request_bytes", lambda *args, **kwargs: json.dumps(payload).encode())
    result = country_sources.refresh_ilostat(tmp_path / "ilo.csv", url="https://example.test/ilo")
    assert result["status"] == "updated"
    assert read_normalized_signal(tmp_path / "ilo.csv", ("value",)) == {"VN": 100.0}


def test_country_sources_does_not_scrape_usgs(tmp_path, monkeypatch):
    monkeypatch.delenv("FAOSTAT_FORESTRY_API_URL", raising=False)
    monkeypatch.delenv("ILOSTAT_WAGES_API_URL", raising=False)
    monkeypatch.delenv("BGS_CEMENT_API_URL", raising=False)
    result = country_sources.refresh_country_sources(tmp_path)
    assert result["sources"]["faostat"]["status"] == "not_configured"
    assert result["sources"]["ilostat"]["status"] == "not_configured"
    assert result["sources"]["bgs_cement"]["status"] == "not_configured"
    assert result["sources"]["usgs"]["status"] == "not_used"


def test_bgs_cement_uses_finished_production_only(tmp_path, monkeypatch):
    payload = {"features": [
        {"properties": {"country_iso2_code": "VN", "year": "2022-01-01T00:00:00", "quantity": 100, "bgs_statistic_type_trans": "Production", "bgs_commodity_trans": "cement, finished"}},
        {"properties": {"country_iso2_code": "VN", "year": "2022-01-01T00:00:00", "quantity": 40, "bgs_statistic_type_trans": "Production", "bgs_commodity_trans": "cement  clinker"}},
        {"properties": {"country_iso2_code": "VN", "year": "2021-01-01T00:00:00", "quantity": 90, "bgs_statistic_type_trans": "Production", "bgs_commodity_trans": "cement, finished"}},
    ]}
    monkeypatch.setattr(country_sources, "_request_bytes", lambda *args, **kwargs: json.dumps(payload).encode())
    result = country_sources.refresh_bgs_cement(tmp_path / "cement.csv", url="https://example.test/bgs")
    assert result["status"] == "updated"
    assert read_normalized_signal(tmp_path / "cement.csv", ("value",)) == {"VN": 100.0}
