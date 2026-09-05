from app.routers import regions


def test_region_detail_exposes_precomputed_market_layers(monkeypatch):
    class Profile:
        def get(self, _code):
            return {"country_code": "DE", "country_name": "Germany"}

    class Market:
        def list_local_opportunities_for_api(self, _code):
            return [{"track": "woodworking", "raw_local_score": 1.0, "calibrated_score": .5}]

        def list_area_overlap_for_api(self, _code):
            return [{"area_id_a": "DE:ADM1:1", "area_id_b": "DE:ADM2:2", "overlap_a_to_b": .5}]
        def list_area_opportunity_summaries(self, _code): return [{"area_id": "DE:ADM1:1"}]
        def list_city_opportunity_summaries(self, _code): return [{"city_id": "DE:CITY:1"}]

    monkeypatch.setattr(regions, "RegionRepository", Profile)
    monkeypatch.setattr(regions, "MarketRepository", Market)
    result = regions.region_details("DE")
    assert result["local_opportunities"][0]["calibrated_score"] == .5
    assert result["area_opportunities"]
    assert result["city_status"] == "ready"
    assert result["overlap_status"] == "ready"


def test_overlap_unavailable_is_explicit(monkeypatch):
    class Profile:
        def get(self, _code): return {"country_code": "KR", "country_name": "South Korea"}

    class Market:
        def list_local_opportunities_for_api(self, _code): return []
        def list_area_overlap_for_api(self, _code): return []
        def list_area_opportunity_summaries(self, _code): return []
        def list_city_opportunity_summaries(self, _code): return []

    monkeypatch.setattr(regions, "RegionRepository", Profile)
    monkeypatch.setattr(regions, "MarketRepository", Market)
    result = regions.region_details("KR")
    assert result["overlap_status"] == "unavailable"
    assert result["overlap_unavailable_reason"] == "insufficient_local_hierarchy"
    assert result["city_opportunities"] == []
