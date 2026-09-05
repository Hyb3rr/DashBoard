"""Read GHSL UCDB urban-centre polygons without mutating application state."""
from __future__ import annotations
import sqlite3
from pathlib import Path
from typing import Any, Iterator
import pycountry
from pyproj import Transformer
from shapely import from_wkb
from shapely.geometry import Polygon

GHSL_GEOMETRY_VERSION = "ghsl_ucdb_r2024a"
_TO_MOLLWEIDE = Transformer.from_crs("EPSG:4326", "ESRI:54009", always_xy=True)

def country_name(iso3: str) -> str:
    item = pycountry.countries.get(alpha_3=iso3.upper())
    return item.name if item else iso3.upper()

def _gpkg_wkb(blob: bytes):
    if not blob or len(blob) < 8 or blob[:2] != b"GP":
        return None
    envelope = {0: 0, 1: 32, 2: 48, 3: 48, 4: 64}.get((blob[3] >> 1) & 7, 0)
    return from_wkb(blob[8 + envelope:])

def h3_polygon_mollweide(cell_id: str) -> Polygon:
    import h3
    boundary = h3.cell_to_boundary(cell_id)
    points = [_TO_MOLLWEIDE.transform(lon, lat) for lat, lon in boundary]
    return Polygon(points + [points[0]])

def iter_city_polygons(path: Path, iso3: str, city_ids: set[str] | None = None) -> Iterator[dict[str, Any]]:
    wanted = {str(value) for value in city_ids} if city_ids is not None else None
    with sqlite3.connect(path) as conn:
        rows = conn.execute('SELECT ID_UC_G0,GC_UCN_MAI_2025,geom FROM "GHSL_UCDB_THEME_GEOGRAPHY_GLOBE_R2024A" WHERE GC_CNT_GAD_2025=?', (country_name(iso3),))
        for city_id, name, blob in rows:
            source_id = str(city_id)
            if wanted is not None and source_id not in wanted:
                continue
            geometry = _gpkg_wkb(blob)
            if geometry is not None and not geometry.is_empty and geometry.is_valid:
                yield {"source_id": source_id, "name": str(name or source_id), "geometry": geometry}
