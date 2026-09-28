import json

from app.core.vietnam_geography import PROVINCES
import app.services.province_profile as profiles


def _isolate_profile_paths(monkeypatch, tmp_path):
    foundation = tmp_path / "foundation"
    enrichment = tmp_path / "enrichment"
    foundation.mkdir(parents=True, exist_ok=True)
    enrichment.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(profiles, "FOUNDATION", foundation)
    monkeypatch.setattr(profiles, "ENRICHMENT", enrichment)
    monkeypatch.setattr(profiles, "CURRENT_INDICATORS", enrichment / "current.json")
    monkeypatch.setattr(profiles, "FDI_STOCK", enrichment / "fdi-stock.json")
    monkeypatch.setattr(profiles, "INDUSTRIAL_PRESENCE", enrichment / "presence.json")
    return foundation, enrichment


def _write_complete_profile_fixture(monkeypatch, tmp_path):
    _, enrichment = _isolate_profile_paths(monkeypatch, tmp_path)
    codes = [unit["code"] for unit in PROVINCES]
    reported_without_number = {next(unit["code"] for unit in PROVINCES if unit["name"] == "Sơn La"), *codes[-4:]}
    iip_values = {"01": 8.9, "11": 12.0, "33": 15.8}
    current = []
    fdi = []
    enterprises = []
    stock = []
    parks = []
    for index, unit in enumerate(PROVINCES):
        code = unit["code"]
        current_status = "reported_no_numeric_value" if code in reported_without_number else "published"
        current.append({
            "geo_unit_id": code,
            "iip_yoy_pct": iip_values.get(code, 1.0 + index),
            "fdi_registered_period_usd_million": 3751.75 if code == "01" else (None if current_status != "published" else 100.0 + index),
            "fdi_status": current_status,
        })
        fdi.append({
            "geo_unit_id": code,
            "total_registered_fdi_usd_million": 1169.4 if code == "25" else 100.0 + index,
            "reference_period": "2025",
            "limitation": "Deterministic test source.",
        })
        enterprises.append({
            "geo_unit_id": code,
            "tracks": {"woodworking": {"value": 10 + index}, "metalworking": {"value": 20 + index}},
        })
        stock.append({
            "geo_unit_id": code,
            "fdi_stock_cumulative_usd_million": 500.0 + index,
            "status": "published",
            "reference_period": "cumulative_to_test_date",
        })
        if index < 2:
            parks.append({"geo_unit_id": code, "industrial_park_count": index + 1})

    fdi.append({
        "geo_unit_id": codes[0],
        "total_registered_fdi_usd_million": 200.0,
        "reference_period": "2026-07",
        "limitation": "Deterministic latest-period fixture.",
    })
    (enrichment / "current.json").write_text(json.dumps({"records": current}), encoding="utf-8")
    (enrichment / "province_fdi_context.json").write_text(json.dumps({"records": fdi}), encoding="utf-8")
    (enrichment / "province_enterprise_context.json").write_text(json.dumps({"records": enterprises}), encoding="utf-8")
    (enrichment / "fdi-stock.json").write_text(json.dumps({"records": stock}), encoding="utf-8")
    (enrichment / "province_industrial_park_context.json").write_text(json.dumps({"records": parks}), encoding="utf-8")


def test_province_payload_has_34_units_and_city_overall_score(monkeypatch, tmp_path):
    _write_complete_profile_fixture(monkeypatch, tmp_path)
    payload = profiles.build_vietnam_province_profile()
    assert payload["scope"] == "VN"
    assert len(payload["provinces"]) == 34
    assert payload["no_composite_score"] is False
    assert payload["city_overall_score_version"] == "city-overall-v1"
    assert all("city_overall_opportunity" in row for row in payload["provinces"])
    assert "province_potential_score" not in payload
    assert payload["coverage"]["relevant_enterprises"] == 34
    assert payload["coverage_detail"]["relevant_enterprises"] == {"label": "Relevant enterprises", "available": 34, "total": 34, "source_status": "complete"}
    assert payload["coverage_detail"]["iip"]["available"] == 34
    assert payload["coverage_detail"]["total_registered_fdi_usd_million"]["available"] == 29
    assert payload["coverage_detail"]["total_registered_fdi_usd_million"]["reported_without_numeric"] == 5
    assert payload["coverage_detail"]["fdi_stock_cumulative_usd_million"]["available"] == 34
    assert all(row["province_investment_momentum"]["cumulative_stock"]["status"] == "published" for row in payload["provinces"])
    assert payload["coverage_detail"]["communes_with_industrial_park"]["available"] == 0
    assert payload["coverage_detail"]["industrial_park_count"]["available"] == 2
    assert payload["provinces"][0]["relevant_enterprises"]["tracks"]["woodworking"]["value"] is not None


def test_missing_context_stays_unknown_or_null(monkeypatch, tmp_path):
    _write_complete_profile_fixture(monkeypatch, tmp_path)
    payload = profiles.build_vietnam_province_profile()
    unknown = [row for row in payload["provinces"] if row["status"]["industrial_parks"] == "unknown"]
    assert unknown
    assert all(row["industrial_park_context"]["occupancy_rate_pct"] is None for row in unknown)
    assert all(row["industrial_park_context"]["limitation"] for row in unknown)


def test_nso_identity_aliases_and_last_usable_fdi_are_not_lost_to_newer_null_rows(monkeypatch, tmp_path):
    _write_complete_profile_fixture(monkeypatch, tmp_path)
    payload = profiles.build_vietnam_province_profile()
    by_name = {row["province_name"]: row for row in payload["provinces"]}
    assert by_name["Hà Nội"]["manufacturing_activity"]["iip"] == 8.9
    assert by_name["Điện Biên"]["manufacturing_activity"]["iip"] == 12.0
    assert by_name["Hưng Yên"]["manufacturing_activity"]["iip"] == 15.8
    assert by_name["Hưng Yên"]["manufacturing_activity"]["historical_legacy_iip"] is None
    assert by_name["Phú Thọ"]["province_investment_momentum"]["total_registered_fdi_usd_million"] == 1169.4
    assert by_name["Phú Thọ"]["province_investment_momentum"]["reference_period"] == "2025"
    assert by_name["Phú Thọ"]["province_investment_momentum"]["latest_source_period"] == "2026-07"
    assert "Latest source period 2026-07" in by_name["Phú Thọ"]["province_investment_momentum"]["limitation"]
    assert by_name["Hà Nội"]["province_investment_momentum"]["current_period"]["value"] == 3751.75
    assert by_name["Sơn La"]["province_investment_momentum"]["current_period"]["status"] == "reported_no_numeric_value"
    assert by_name["Sơn La"]["province_investment_momentum"]["current_period"]["value"] is None


def test_iip_is_labeled_as_industrial_production_not_manufacturing_only(monkeypatch, tmp_path):
    _write_complete_profile_fixture(monkeypatch, tmp_path)
    payload = profiles.build_vietnam_province_profile()
    assert all(row["manufacturing_activity"]["indicator_name"] == "Industrial production index (IIP), year-on-year" for row in payload["provinces"])


def test_profile_can_build_rows_without_calculating_overall_scores(monkeypatch, tmp_path):
    _write_complete_profile_fixture(monkeypatch, tmp_path)

    def unexpected_score_calculation(_rows):
        raise AssertionError("include_overall=False must not invoke the score engine")

    monkeypatch.setattr(profiles, "score_rows", unexpected_score_calculation)
    payload = profiles.build_vietnam_province_profile(include_overall=False)

    assert len(payload["provinces"]) == 34
    assert all(row["city_overall_opportunity"]["score"] is None for row in payload["provinces"])
    assert all(row["city_overall_opportunity"]["status"] == "snapshot_unavailable" for row in payload["provinces"])


def test_clean_missing_fdi_stock_remains_null_and_not_ingested(monkeypatch, tmp_path):
    _isolate_profile_paths(monkeypatch, tmp_path)
    payload = profiles.build_vietnam_province_profile()
    stocks = [row["province_investment_momentum"]["cumulative_stock"] for row in payload["provinces"]]

    assert len(stocks) == len(PROVINCES) == 34
    assert all(stock["value"] is None and stock["status"] == "not_ingested" for stock in stocks)
    assert all(stock["reference_period"] is None for stock in stocks)
    assert payload["coverage_detail"]["fdi_stock_cumulative_usd_million"] == {
        "label": "Cumulative FDI stock", "available": 0, "total": 34, "source_status": "not_ingested"
    }


def test_fdi_stock_context_handles_none_without_inventing_values():
    assert profiles._fdi_stock_context(None) == {
        "value": None,
        "status": "not_ingested",
        "reference_period": None,
        "source_name": None,
        "source_url": "province_fdi_stock_context.json",
        "retrieved_at": None,
        "source_geography": None,
        "unit": "USD million",
        "limitation": "FIA Appendix III attachment has not been ingested.",
    }
