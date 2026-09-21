from app.core.city_overall_opportunity import score_rows


def _row(code, enterprises, iip=None, flow=None, stock=None, local=None):
    return {
        "geo_unit_id": code,
        "relevant_enterprises": {"tracks": {"woodworking": {"value": enterprises}, "metalworking": {"value": enterprises}}},
        "manufacturing_activity": {"iip": iip, "current_iip_yoy_pct": iip},
        "province_investment_momentum": {
            "current_period": {"value": flow, "status": "published" if flow is not None else "reported_no_numeric_value"},
            "cumulative_stock": {"value": stock, "status": "published" if stock is not None else "not_ingested"},
        },
        "industrial_infrastructure_context": {"commune_ip_presence_rate_pct": local},
        "industrial_park_context": {},
    }


def test_overall_score_is_not_a_product_max_and_exposes_components():
    result = score_rows([_row("a", 10, iip=5, flow=10, stock=100), _row("b", 20, iip=10, flow=20, stock=200)])
    assert result["a"]["score"] < result["b"]["score"]
    assert result["a"]["score_type"] == "overall_city_evidence"
    assert "enterprise_base" in result["a"]["components"]


def test_missing_evidence_is_not_zero_and_reduces_confidence():
    result = score_rows([_row("a", 10), _row("b", 20, iip=10)])
    assert result["a"]["score"] is not None
    assert result["a"]["components"]["iip"] is None
    assert result["a"]["evidence_coverage"] < 100


def test_score_renormalizes_available_groups():
    result = score_rows([_row("a", 10, iip=5), _row("b", 20, iip=10)])
    assert result["a"]["score"] is not None
    assert set(result["a"]["available_groups"]) == {"enterprise_base", "iip"}


def test_city_v1_does_not_use_country_demand_or_observed_traffic():
    result = score_rows([_row("a", 10), _row("b", 20)])
    assert "country_demand" not in result["a"]["components"]
    assert "observed_traffic" not in result["a"]["components"]


def test_legacy_iip_cannot_enter_current_overall_score():
    rows = [_row("a", 10), _row("b", 20, iip=10)]
    rows[0]["manufacturing_activity"] = {
        "iip": 99.0,
        "current_iip_yoy_pct": None,
    }
    result = score_rows(rows)
    assert result["a"]["components"]["iip"] is None
    assert "iip" not in result["a"]["available_groups"]


def test_partial_enterprise_evidence_is_missing_not_a_full_component():
    rows = [_row("a", 10), _row("b", 20)]
    rows[0]["relevant_enterprises"]["tracks"]["metalworking"]["value"] = None
    result = score_rows(rows)
    assert result["a"]["components"]["enterprise_base"] is None
    assert "enterprise_base" not in result["a"]["available_groups"]


def test_tied_percentiles_are_mid_ranked_and_sparse_cohorts_are_unavailable():
    tied = score_rows([_row("a", 10), _row("b", 10), _row("c", 20)])
    assert tied["a"]["components"]["enterprise_base"] == 33.3333
    assert score_rows([_row("only", 10)])["only"]["components"]["enterprise_base"] is None


def test_all_vietnam_rows_can_be_backfilled_by_profile_builder():
    from app.services.province_profile import build_vietnam_province_profile
    payload = build_vietnam_province_profile()
    assert len(payload["provinces"]) == 34
    assert all("city_overall_opportunity" in row for row in payload["provinces"])
