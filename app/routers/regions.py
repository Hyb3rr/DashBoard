from fastapi import APIRouter, HTTPException

from ..db.repositories import RegionRepository

router = APIRouter()


@router.get("/api/regions")
def region_list(limit: int = 50):
    return RegionRepository().list(limit=min(max(limit, 1), 200))


@router.get("/api/regions/demand-signal")
def region_demand_signal(limit: int = 50):
    return RegionRepository().demand_signal(min(max(limit, 1), 200))


@router.get("/api/regions/{country_code}")
def region_details(country_code: str):
    data = RegionRepository().get(country_code.upper())
    if not data:
        raise HTTPException(404, "Region profile not found")
    return data
