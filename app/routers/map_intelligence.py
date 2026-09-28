from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query

from ..services.map_intelligence import MapIntelligenceService, RANGE_HOURS


router = APIRouter()


def _parse_time(value: str | None) -> datetime | None:
    """Parse an optional map window timestamp and normalize it to UTC."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HTTPException(400, "invalid map time window") from exc
    return (parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)


@router.get("/api/map/world")
def map_world(range: str = "24h", start: str | None = Query(None), end: str | None = Query(None)):
    """Return global map intelligence for a preset or custom time window."""
    if (start or end) and not (start and end):
        raise HTTPException(400, "custom map window requires both start and end")
    if not start and not end and range not in RANGE_HOURS:
        raise HTTPException(400, "range must be one of: 30m, 1h, 6h, 12h, 24h, 3d, 7d, 30d")
    try:
        return MapIntelligenceService().world(range, _parse_time(start), _parse_time(end))
    except Exception as exc:
        raise HTTPException(503, f"Map intelligence unavailable: {exc}") from exc


@router.get("/api/map/country/{country_code}")
def map_country(country_code: str, range: str = "24h", start: str | None = Query(None), end: str | None = Query(None)):
    """Return country-level map intelligence for a preset or custom window."""
    if (start or end) and not (start and end):
        raise HTTPException(400, "custom map window requires both start and end")
    if not start and not end and range not in RANGE_HOURS:
        raise HTTPException(400, "range must be one of: 30m, 1h, 6h, 12h, 24h, 3d, 7d, 30d")
    try:
        result = MapIntelligenceService().country(country_code, range, _parse_time(start), _parse_time(end))
    except Exception as exc:
        raise HTTPException(503, f"Map intelligence unavailable: {exc}") from exc
    if result is None:
        raise HTTPException(404, "Country map data not found")
    return result
