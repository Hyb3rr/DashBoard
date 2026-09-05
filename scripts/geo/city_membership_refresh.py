"""LC-2A.2: persist true GHSL urban-centre to H3 polygon membership."""
from __future__ import annotations
import json
import os
from pathlib import Path
from typing import Any, Iterable
from app.db.market_repository import MarketRepository
from scripts.geo.ghsl_city_geometry import GHSL_GEOMETRY_VERSION, h3_polygon_mollweide, iter_city_polygons

CITY_MEMBERSHIP_MODEL_VERSION = "lc2a-membership-v1"

def build_memberships(cities: Iterable[dict[str, Any]], cells: Iterable[dict[str, Any]], country: str) -> list[dict[str, Any]]:
    result = []
    for city in cities:
        for cell in cells:
            cell_geometry = h3_polygon_mollweide(cell["h3_cell_id"])
            intersection = city["geometry"].intersection(cell_geometry)
            if intersection.is_empty or cell_geometry.area <= 0 or intersection.area <= 0:
                continue
            result.append({"snapshot_id": cell["snapshot_id"], "country_code": country,
                "city_id": f"{country}:CITY:{city['source_id']}", "h3_cell_id": cell["h3_cell_id"],
                "h3_resolution": cell["h3_resolution"], "intersection_area": round(float(intersection.area), 6),
                "membership_fraction": round(min(1.0, max(0.0, float(intersection.area / cell_geometry.area))), 9),
                "geometry_source": "ghsl_ucdb_r2024a", "geometry_version": GHSL_GEOMETRY_VERSION,
                "membership_status": "ready", "model_version": CITY_MEMBERSHIP_MODEL_VERSION})
    return result

def refresh_city_memberships(repo: MarketRepository, countries: Iterable[str] | None = None) -> dict[str, Any]:
    selected = [str(code).strip().upper() for code in (countries or os.getenv("OSM_COUNTRIES", "DE,NL,BE").split(",")) if str(code).strip()]
    path = Path(os.getenv("GHSL_GEOMETRY_PATH", "data/geography/GHS_UCDB_GLOBE_R2024A.gpkg"))
    reports = {}
    for country in selected:
        try:
            cities = repo.list_city_registry(country)
            cells = repo.list_active_h3_cells(country)
            ids = {str(city["source_id"]) for city in cities}
            items = build_memberships(iter_city_polygons(path, repo.country_iso3(country) or country, ids), cells, country)
            reports[country] = {"status": "updated", "cities_with_polygon": len(ids), "cells_seen": len(cells), "memberships": repo.upsert_city_cell_memberships(items)}
        except Exception as exc:
            reports[country] = {"status": "failed", "error": type(exc).__name__, "message": str(exc)[:240]}
    failed = [code for code, report in reports.items() if report["status"] == "failed"]
    return {"status": "partial" if failed else "completed", "countries": reports, "failed": failed, "model_version": CITY_MEMBERSHIP_MODEL_VERSION}

if __name__ == "__main__":
    from ..db import postgres
    try:
        print(json.dumps(refresh_city_memberships(MarketRepository()), indent=2))
    finally:
        postgres.close_pool()
