from fastapi import APIRouter, HTTPException

from ..db.repositories import RegionRepository
from ..db.market_repository import MarketRepository

router = APIRouter()


@router.get("/api/regions")
def region_list(limit: int = 50):
    return RegionRepository().list(limit=min(max(limit, 1), 200))


@router.get("/api/regions/demand-signal")
def region_demand_signal(limit: int = 50):
    return RegionRepository().demand_signal(min(max(limit, 1), 200))


@router.get("/api/regions/{country_code}")
def region_details(country_code: str):
    code = country_code.upper()
    data = RegionRepository().get(code)
    if not data:
        raise HTTPException(404, "Region profile not found")
    market = MarketRepository()
    local = market.list_local_opportunities_for_api(code)
    overlap = market.list_area_overlap_for_api(code)
    areas = market.list_area_opportunity_summaries(code)
    cities = market.list_city_opportunity_summaries(code)
    data["area_opportunities"] = areas
    data["city_opportunities"] = cities
    data["city_status"] = "ready" if cities else "unavailable"
    data["city_unavailable_reason"] = None if cities else "insufficient_city_summary"
    data["local_opportunities"] = local
    data["overlap"] = overlap
    data["overlap_status"] = "ready" if overlap else "unavailable"
    data["overlap_unavailable_reason"] = None if overlap else "insufficient_local_hierarchy"
    return data
