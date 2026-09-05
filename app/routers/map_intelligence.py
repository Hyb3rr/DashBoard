from fastapi import APIRouter, HTTPException

from ..services.map_intelligence import MapIntelligenceService, RANGE_HOURS


router = APIRouter()


@router.get("/api/map/world")
def map_world(range: str = "24h"):
    if range not in RANGE_HOURS:
        raise HTTPException(400, "range must be one of: 1h, 24h, 7d")
    try:
        return MapIntelligenceService().world(range)
    except Exception as exc:
        raise HTTPException(503, f"Map intelligence unavailable: {exc}") from exc


@router.get("/api/map/country/{country_code}")
def map_country(country_code: str, range: str = "24h"):
    if range not in RANGE_HOURS:
        raise HTTPException(400, "range must be one of: 1h, 24h, 7d")
    try:
        result = MapIntelligenceService().country(country_code, range)
    except Exception as exc:
        raise HTTPException(503, f"Map intelligence unavailable: {exc}") from exc
    if result is None:
        raise HTTPException(404, "Country map data not found")
    return result
