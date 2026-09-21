from app.routers import regions
from pathlib import Path


def test_region_detail_uses_province_marketing_view():
    template = (Path(__file__).parents[1] / "app/web/templates/region_detail.html").read_text()
    assert "Province / city profiles" in template
    assert "Observed enterprise base" in template
    assert "Local Opportunities" not in template


def test_region_detail_exposes_precomputed_market_layers(monkeypatch):
    class Profile:
        def get(self, _code):
            return {"country_code": "DE", "country_name": "Germany"}

    class Market:
        def list_local_opportunities_for_api(self, _code):
            return [{"track": "woodworking", "raw_local_score": 1.0, "calibrated_score": .5,
                     "evidence_components": {"osm_feature_count": 3}}]

        def list_area_overlap_for_api(self, _code):
            return [{"area_id_a": "DE:ADM1:1", "area_id_b": "DE:ADM2:2", "overlap_a_to_b": .5}]
        def list_area_opportunity_summaries(self, _code): return [{"area_id": "DE:ADM1:1"}]
        def list_city_opportunity_summaries(self, _code): return [{"city_id": "DE:CITY:1"}]
        def list_market_potential_summaries(self, _code): return [{"product_id": "cnc_router", "score": 70}]
        def list_latest_industrial_demand_evidence(self, _code, _snapshot_id=None): return [{"snapshot_id": "s", "model_version": "market-demand-v2"}]
        def get_latest_industrial_demand_snapshot(self, _code): return {"snapshot_id": "s", "model_version": "market-demand-v2"}

    monkeypatch.setattr(regions, "RegionRepository", Profile)
    monkeypatch.setattr(regions, "MarketRepository", Market)
    result = regions.region_details("DE")
    assert result["local_opportunities"][0]["calibrated_score"] == .5
    assert result["local_opportunities"][0]["evidence_components"]["osm_feature_count"] == 3
    assert result["area_opportunities"]
    assert result["city_status"] == "ready"
    assert result["market_product_opportunities"][0]["score"] == 70
    assert result["overlap_status"] == "ready"
    assert result["industrial_demand"]["status"] == "published"
    assert result["industrial_demand"]["model_version"] == "market-demand-v2"


def test_region_detail_does_not_render_obsolete_local_opportunity_filters():
    template = Path("app/web/templates/region_detail.html").read_text()
    assert "data-market-track" not in template
    assert "market-filter" not in template


def test_overlap_unavailable_is_explicit(monkeypatch):
    class Profile:
        def get(self, _code): return {"country_code": "KR", "country_name": "South Korea"}

    class Market:
        def list_local_opportunities_for_api(self, _code): return []
        def list_area_overlap_for_api(self, _code): return []
        def list_area_opportunity_summaries(self, _code): return []
        def list_city_opportunity_summaries(self, _code): return []
        def list_market_potential_summaries(self, _code): return []

    monkeypatch.setattr(regions, "RegionRepository", Profile)
    monkeypatch.setattr(regions, "MarketRepository", Market)
    result = regions.region_details("KR")
    assert result["overlap_status"] == "unavailable"
    assert result["overlap_unavailable_reason"] == "insufficient_local_hierarchy"
    assert result["city_opportunities"] == []
