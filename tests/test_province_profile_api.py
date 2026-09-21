from app.services.province_profile import build_vietnam_province_profile


def test_province_payload_has_34_units_and_city_overall_score():
    payload = build_vietnam_province_profile()
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


def test_missing_context_stays_unknown_or_null():
    payload = build_vietnam_province_profile()
    unknown = [row for row in payload["provinces"] if row["status"]["industrial_parks"] == "unknown"]
    assert unknown
    assert all(row["industrial_park_context"]["occupancy_rate_pct"] is None for row in unknown)
    assert all(row["industrial_park_context"]["limitation"] for row in unknown)


def test_nso_identity_aliases_and_last_usable_fdi_are_not_lost_to_newer_null_rows():
    payload = build_vietnam_province_profile()
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


def test_iip_is_labeled_as_industrial_production_not_manufacturing_only():
    payload = build_vietnam_province_profile()
    assert all(row["manufacturing_activity"]["indicator_name"] == "Industrial production index (IIP), year-on-year" for row in payload["provinces"])
