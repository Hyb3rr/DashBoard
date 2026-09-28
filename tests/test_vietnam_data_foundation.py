from urllib.error import HTTPError

from scripts.market import vietnam_data_foundation as foundation
from scripts.market.vietnam_data_foundation import PX_TABLES, PX_INDUSTRY_TABLES, HS6_PRODUCT_MAP, _all_query


def test_foundation_keeps_industry_and_province_datasets_separate():
    assert PX_TABLES["E05.03.px"] == "national_industry_structure"
    assert PX_TABLES["E05.04.px"] == "province_enterprise_structure"


def test_px_query_selects_all_dimensions_without_allocating_geography():
    metadata = {"variables": [{"code": "Industry", "values": ["1", "2"]}, {"code": "Year", "values": ["0", "1"]}]}
    query = _all_query(metadata, "2024")
    assert query["query"][0]["selection"]["values"] == ["1", "2"]
    assert query["response"]["format"] == "csv"


def test_year_selection_uses_year_dimension_not_last_dimension():
    metadata = {"variables": [{"code": "Activity", "values": ["a"]}, {"code": "Year", "values": ["2023", "2024"]}, {"code": "Size", "values": ["small", "large"]}]}
    assert _all_query(metadata, "2024")["query"][1]["selection"]["values"] == ["2024"]


def test_hs6_mapping_covers_fourteen_sellable_products_without_furniture_proxy():
    assert len(HS6_PRODUCT_MAP) == 14
    assert "furniture_export_proxy" not in HS6_PRODUCT_MAP
    assert "846520" in HS6_PRODUCT_MAP["cnc_router"]


def test_current_momentum_uses_official_nso_iip_tables():
    assert PX_INDUSTRY_TABLES == {"E07.01.px": "national_iip_by_industry", "E07.02.px": "province_iip"}


def test_px_source_collection_preserves_order_and_reports_independent_failures(tmp_path, monkeypatch):
    calls = []

    def fake_download(table, output, **kwargs):
        calls.append((table, kwargs.get("base", foundation.PX_BASE)))
        if table == "E05.03.px":
            raise HTTPError("https://example.test", 503, "unavailable", {}, None)
        return {"dataset": kwargs.get("dataset") or PX_TABLES.get(table), "table": table}

    monkeypatch.setattr(foundation, "download_px", fake_download)

    reports = foundation._download_px_sources(tmp_path)

    assert [table for table, _ in calls] == [*PX_TABLES, *PX_INDUSTRY_TABLES]
    assert reports[0]["status"] == "failed"
    assert reports[0]["rows"] is None
    assert reports[0]["limitation"] == "Source fetch failed; row count is unknown."
    assert reports[-1] == {
        "dataset": "province_iip",
        "table": "E07.02.px",
        "status": "loaded",
    }
    assert calls[-1][1] == foundation.PX_INDUSTRY_BASE
