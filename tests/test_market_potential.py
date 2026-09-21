from pathlib import Path

from app.core.market_potential import (
    blend_scores,
    city_fit_score,
    confidence,
    country_product_prior,
    percentile_rank,
    sales_validation_score,
    minmax_normalize,
)
from app.db import market_repository


class _Result:
    def fetchall(self):
        return []


class _Connection:
    def __init__(self):
        self.batches = []

    def cursor(self):
        return self

    def executemany(self, sql, values):
        self.batches.append((sql, list(values)))

    def execute(self, sql, params=()):
        return _Result()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _Transaction:
    def __init__(self, conn):
        self.conn = conn

    def __enter__(self):
        return self.conn

    def __exit__(self, *exc):
        return False


def test_country_prior_preserves_missing_values_and_renormalises():
    assert country_product_prior({"hs_import": 1.0, "relevant_export": 0.5}, "woodworking") == 81.8182
    assert country_product_prior({}, "woodworking") is None


def test_minmax_normalize_treats_fractional_raw_values_as_raw_values():
    result = minmax_normalize({"a": 0.5, "b": 1.0, "c": 2.0})
    assert result == {"a": 0.0, "b": 0.3333333333333333, "c": 1.0}


def test_city_fit_requires_geometry_derived_density_and_peer_percentile():
    assert city_fit_score({"business_density_per_km2": 0.8, "sector_relevant_business_share": 0.6}, [0.2, 0.5, 0.7]) == 100.0
    assert city_fit_score({"business_density_per_km2": None, "sector_relevant_business_share": 0.6}, [0.2]) is None


def test_public_city_candidates_are_ranked_by_population_without_business_tier():
    from scripts.market.seed_geo_candidates import select_candidates

    cities = [
        {"geoname_id": "2", "country_code": "BB", "display_name": "B city", "population": 20, "lat": 1, "lng": 2},
        {"geoname_id": "1", "country_code": "BB", "display_name": "A city", "population": 30, "lat": 1, "lng": 2},
        {"geoname_id": "3", "country_code": "AA", "display_name": "C city", "population": 40, "lat": 1, "lng": 2},
    ]
    result = select_candidates(cities, ["BB", "AA"], max_countries=2, per_country=1)
    assert [row["display_name"] for row in result] == ["A city", "C city"]


def test_candidate_mode_defaults_to_vietnam_and_global_mode_is_configurable(monkeypatch):
    import importlib
    import scripts.market.seed_geo_candidates as candidates
    assert candidates.PRIORITY_COUNTRY == "VN"
    monkeypatch.setenv("GEO_CANDIDATE_MODE", "global")
    importlib.reload(candidates)
    assert candidates.CANDIDATE_MODE == "global"
    monkeypatch.delenv("GEO_CANDIDATE_MODE")
    importlib.reload(candidates)


def test_blend_moves_smoothly_when_one_rfq_is_added():
    first = blend_scores(40, 70, 80, 1)
    second = blend_scores(40, 70, 80, 2)
    assert first["score_type"] == "estimated"
    assert second["score"] > first["score"]
    assert second["weights"]["internal"] > first["weights"]["internal"]
    assert second["weights"]["internal"] - first["weights"]["internal"] < 0.2


def test_blend_uses_default_country_city_weights_and_renormalizes_missing_sources():
    both = blend_scores(60, 80, None, 0)
    country_only = blend_scores(60, None, None, 0)
    city_only = blend_scores(None, 80, None, 0)
    assert both["weights"] == {"internal": 0.0, "city": 0.4, "country": 0.6}
    assert both["score"] == 68.0
    assert country_only["weights"] == {"internal": 0.0, "city": 0.0, "country": 1.0}
    assert country_only["score"] == 60.0
    assert city_only["weights"] == {"internal": 0.0, "city": 1.0, "country": 0.0}
    assert city_only["score"] == 80.0


def test_nearest_city_fit_respects_match_radius():
    from scripts.market.market_potential_refresh import nearest_city_fit

    city = {"track": "woodworking", "city_id": "VN:CITY:1", "city_calibrated_score": 75,
            "centroid_lat": 10.8, "centroid_lon": 106.7}
    close = {"lat": 10.81, "lng": 106.71}
    far = {"lat": 21.0, "lng": 105.8}
    assert nearest_city_fit(close, [city], "woodworking")[0] == 75.0
    assert nearest_city_fit(far, [city], "woodworking")[0] is None


def test_competition_normalization_keeps_partial_sources_explicit():
    from scripts.market.market_potential_refresh import normalize_competition

    assert normalize_competition({"a": 1, "b": 3}) == {"a": 0.0, "b": 100.0}
    assert normalize_competition({"a": 2}) == {"a": 50.0}
    assert normalize_competition({}) == {}


def test_missing_sources_do_not_become_observed_zero():
    result = blend_scores(None, None, None, 0)
    assert result["score"] is None
    assert result["score_type"] == "prior"


def test_sales_validation_is_ranked_and_missing_rfqs_stay_missing():
    assert sales_validation_score({"rfq_count": 1.0, "win_rate": 1.0}, [0.5, 1.0]) == 100.0
    from scripts.market.market_potential_refresh import build_sales_validation

    rows = [
        {"geo_unit_id": "VN-A", "product_id": "cnc_router", "rfq_count_12m": 10,
         "quoted_count": 8, "win_rate": 0.5, "avg_deal_value_usd": 1000, "has_repeat_customer": True},
        {"geo_unit_id": "VN-B", "product_id": "cnc_router", "rfq_count_12m": 2,
         "quoted_count": 1, "win_rate": 0.0, "avg_deal_value_usd": 500, "has_repeat_customer": False},
    ]
    result = build_sales_validation(rows)
    assert result[("VN-A", "cnc_router")]["score"] > result[("VN-B", "cnc_router")]["score"]
    assert build_sales_validation([]) == {}


def test_confidence_exposes_group_coverage():
    result = confidence({"country": 80, "city": None, "internal": None, "competition": None, "labor": 50}, 0.8, 1.0, False)
    assert result == {"confidence": 56.0, "data_coverage": 0.4, "data_coverage_total": 5}


def test_repository_upsert_is_batch_and_json_encodes_explanations(monkeypatch):
    conn = _Connection()
    monkeypatch.setattr(market_repository, "transaction", lambda: _Transaction(conn))
    count = market_repository.MarketRepository().upsert_market_potential_summaries([{
        "snapshot_id": "2026-09", "geo_unit_id": "VN-BD", "country_code": "VN", "product_id": "cnc_router",
        "score": None, "score_type": "prior", "confidence": 20.0, "limitations": ["city_fit unavailable"],
    }])
    assert count == 1
    sql, values = conn.batches[0]
    assert "market_city_product_summary" in sql
    assert values[0][4] is None
    assert values[0][21] == []


def test_foundation_migration_declares_product_specific_key():
    sql = Path("infra/postgres/020_market_potential_foundation.sql").read_text()
    assert "PRIMARY KEY (snapshot_id, geo_unit_id, product_id)" in sql
    assert "score DOUBLE PRECISION" in sql


def test_bootstrap_seeds_all_product_tracks_and_source_registry():
    sql = Path("infra/postgres/024_market_potential_bootstrap.sql").read_text()
    assert sql.count("ON CONFLICT (product_id)") == 1
    assert sql.count("ON CONFLICT (source_id)") == 1
    assert "market_country_product_prior" in sql
    assert "edge_bander" in sql
    assert "internal_crm" in sql
