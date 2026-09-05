"""Build the Phase 3 geography identity foundation.

This job is scheduler/deployment owned. It does not run in FastAPI startup,
the collector, or any realtime request path. Source payloads are normalized
to identity/provenance records; no opportunity score is calculated here.
"""

from __future__ import annotations

import json
import os
import hashlib
import csv
import io
import shutil
import sqlite3
import struct
import tempfile
import zipfile
import math
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pycountry

from app.core.market_catalog import catalog_rows
from app.db.market_repository import MarketRepository
from app.db.postgres import close_pool
from app.config.settings import DATA_DIR


DEFAULT_TIMEOUT = 30.0
DEFAULT_MIN_ADM2_AREAS = 5
DEFAULT_MIN_ADM2_CITY_COVERAGE = 0.60
GHSL_CACHE_DIR = DATA_DIR / "geography"
GHSL_ARCHIVE_PATH = GHSL_CACHE_DIR / "GHS_UCDB_GLOBE_R2024A.zip"
GEOBOUNDARIES_CACHE_DIR = GHSL_CACHE_DIR / "geoboundaries"


def _boundary_artifacts_available(iso3: str, state: dict[str, Any]) -> bool:
    """A done geography job is valid only while its required files exist."""
    required_levels = {1}
    if str(state.get("current_step", "")).casefold() == "adm2":
        required_levels.add(2)
    return all(
        (GEOBOUNDARIES_CACHE_DIR / iso3.upper() / f"ADM{level}.json").is_file()
        and (GEOBOUNDARIES_CACHE_DIR / iso3.upper() / f"ADM{level}.json").stat().st_size > 0
        for level in required_levels
    )


def _properties(feature: dict[str, Any]) -> dict[str, Any]:
    value = feature.get("properties") or {}
    return value if isinstance(value, dict) else {}


def _number(value: Any) -> float | None:
    try:
        result = float(value)
    except (TypeError, ValueError):
        return None
    return result if -180 <= result <= 180 else None


def _point(feature: dict[str, Any]) -> tuple[float, float] | None:
    geometry = feature.get("geometry") or {}
    if geometry.get("type") == "Point" and len(geometry.get("coordinates") or []) >= 2:
        lon, lat = geometry["coordinates"][:2]
        lat, lon = _number(lat), _number(lon)
        return (lat, lon) if lat is not None and lon is not None else None
    props = _properties(feature)
    lat = _number(props.get("latitude", props.get("lat", props.get("centroid_lat"))))
    lon = _number(props.get("longitude", props.get("lon", props.get("centroid_lon"))))
    return (lat, lon) if lat is not None and lon is not None else None


def _bbox(coordinates: Any) -> tuple[float, float, float, float] | None:
    points: list[tuple[float, float]] = []
    def visit(value: Any) -> None:
        if isinstance(value, (list, tuple)) and len(value) >= 2 and all(isinstance(x, (int, float)) for x in value[:2]):
            points.append((float(value[1]), float(value[0])))
        elif isinstance(value, (list, tuple)):
            for child in value:
                visit(child)
    visit(coordinates)
    if not points:
        return None
    lats, lons = zip(*points)
    return min(lats), min(lons), max(lats), max(lons)


def _polygon_parts(geometry: dict[str, Any]) -> list[list[list[tuple[float, float]]]]:
    """Return polygons as [polygon][ring][(lat, lon)] for point-in-polygon."""
    kind, coords = geometry.get("type"), geometry.get("coordinates")
    if kind == "Polygon":
        polygons = [coords]
    elif kind == "MultiPolygon":
        polygons = coords or []
    else:
        return []
    result = []
    for polygon in polygons:
        rings = []
        for ring in polygon or []:
            rings.append([(float(point[1]), float(point[0])) for point in ring if len(point) >= 2])
        if rings and rings[0]:
            result.append(rings)
    return result


def _inside_ring(point: tuple[float, float], ring: list[tuple[float, float]]) -> bool:
    lat, lon = point
    inside = False
    for index, (y1, x1) in enumerate(ring):
        y2, x2 = ring[index - 1]
        crosses = (x1 > lon) != (x2 > lon)
        if crosses and lat < (y2 - y1) * (lon - x1) / (x2 - x1) + y1:
            inside = not inside
    return inside


def _inside(feature: dict[str, Any], point: tuple[float, float]) -> bool:
    for polygon in _polygon_parts(feature.get("geometry") or {}):
        if _inside_ring(point, polygon[0]) and not any(_inside_ring(point, hole) for hole in polygon[1:]):
            return True
    return False


def _bbox_candidates(boundaries: list[dict[str, Any]], point: tuple[float, float]) -> list[dict[str, Any]]:
    lat, lon = point
    return [
        area for area in boundaries
        if (area.get("bbox_min_lat") is None or area["bbox_min_lat"] <= lat <= area["bbox_max_lat"])
        and (area.get("bbox_min_lon") is None or area["bbox_min_lon"] <= lon <= area["bbox_max_lon"])
    ]


def _feature_collection(payload: dict[str, Any]) -> list[dict[str, Any]]:
    if payload.get("type") == "FeatureCollection":
        return [item for item in payload.get("features", []) if isinstance(item, dict)]
    if payload.get("type") == "Feature":
        return [payload]
    return []


def normalize_boundaries(payload: dict[str, Any], country_code: str, admin_level: int,
                         source: str = "geoboundaries") -> list[dict[str, Any]]:
    """Normalize GeoJSON ADM features without storing full geometry in PostgreSQL."""
    result = []
    for index, feature in enumerate(_feature_collection(payload)):
        props = _properties(feature)
        source_id = str(props.get("boundaryID") or props.get("id") or feature.get("id") or index)
        name = str(props.get("boundaryName") or props.get("name") or props.get("shapeName") or source_id)
        bounds = _bbox((feature.get("geometry") or {}).get("coordinates"))
        result.append({
            "area_id": f"{country_code}:ADM{admin_level}:{source_id}",
            "country_code": country_code,
            "name": name,
            "area_type": "administrative_area",
            "admin_level": admin_level,
            "granularity_class": "normal",
            "source": source,
            "source_id": source_id,
            "centroid_lat": _number(props.get("centroid_lat")),
            "centroid_lon": _number(props.get("centroid_lon")),
            "bbox_min_lat": bounds[0] if bounds else None,
            "bbox_min_lon": bounds[1] if bounds else None,
            "bbox_max_lat": bounds[2] if bounds else None,
            "bbox_max_lon": bounds[3] if bounds else None,
            "geometry_ref": {"source": source, "source_id": source_id, "boundary_year": props.get("boundaryYearRepresented")},
            "_feature": feature,
        })
    return result


def normalize_cities(payload: dict[str, Any], country_code: str, source: str = "ghsl") -> list[dict[str, Any]]:
    result = []
    for index, feature in enumerate(_feature_collection(payload)):
        point = _point(feature)
        if not point:
            continue
        props = _properties(feature)
        source_id = str(props.get("id") or props.get("ID") or props.get("city_id") or feature.get("id") or index)
        name = str(props.get("name") or props.get("NAME") or props.get("city_name") or source_id)
        result.append({
            "area_id": f"{country_code}:CITY:{source_id}",
            "country_code": country_code,
            "name": name,
            "area_type": "city",
            "admin_level": None,
            "granularity_class": "normal",
            "source": source,
            "source_id": source_id,
            "centroid_lat": point[0], "centroid_lon": point[1],
            "geometry_ref": {"source": source, "source_id": source_id},
            "_feature": feature,
        })
    return result


def choose_adaptive_level(cities: list[dict[str, Any]], adm1: list[dict[str, Any]], adm2: list[dict[str, Any]],
                          min_adm2_areas: int = DEFAULT_MIN_ADM2_AREAS,
                          min_adm2_city_coverage: float = DEFAULT_MIN_ADM2_CITY_COVERAGE) -> int:
    """Choose ADM2 only when it provides enough usable city parent coverage."""
    if len(adm2) < min_adm2_areas or not cities:
        return 1
    covered = sum(any(_inside(area["_feature"], (city["centroid_lat"], city["centroid_lon"]))
                      for area in _bbox_candidates(adm2, (city["centroid_lat"], city["centroid_lon"])))
                 for city in cities)
    return 2 if covered / len(cities) >= min_adm2_city_coverage else 1


def assign_city_parents(cities: list[dict[str, Any]], boundaries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    for city in cities:
        point = (city["centroid_lat"], city["centroid_lon"])
        candidates = _bbox_candidates(boundaries, point)
        parent = next((area for area in candidates if _inside(area["_feature"], point)), None)
        city["parent_area_id"] = parent["area_id"] if parent else None
    return cities


def assign_boundary_parents(children: list[dict[str, Any]], parents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Assign ADM2 -> ADM1 parents from cached boundary geometry."""
    for child in children:
        bounds = (child.get("bbox_min_lat"), child.get("bbox_min_lon"),
                  child.get("bbox_max_lat"), child.get("bbox_max_lon"))
        if any(value is None for value in bounds):
            child["parent_area_id"] = None
            continue
        point = ((bounds[0] + bounds[2]) / 2, (bounds[1] + bounds[3]) / 2)
        parent = next((area for area in _bbox_candidates(parents, point) if _inside(area["_feature"], point)), None)
        child["parent_area_id"] = parent["area_id"] if parent else None
    return children


def persist_country(repo: MarketRepository, country_code: str, cities: list[dict[str, Any]],
                    adm1: list[dict[str, Any]], adm2: list[dict[str, Any]], source_version: str = "unknown") -> dict[str, Any]:
    level = choose_adaptive_level(cities, adm1, adm2)
    selected = adm2 if level == 2 else adm1
    if level == 2:
        assign_boundary_parents(selected, adm1)
    cities = assign_city_parents(cities, selected)
    registry = (adm1 + selected if level == 2 else selected) + cities
    areas = []
    for item in registry:
        clean = {key: value for key, value in item.items() if key != "_feature"}
        if clean.get("area_type") == "administrative_area":
            clean["source_id"] = f"ADM{clean['admin_level']}:{clean['source_id']}"
        areas.append(clean)
    sources = [{"area_id": item["area_id"], "source_name": item["source"], "source_object_id": item["source_id"], "source_version": source_version, "source_confidence": 80 if item["source"] == "ghsl" else 90} for item in areas]
    repo.upsert_areas(areas)
    repo.upsert_area_sources(sources)
    return {"country_code": country_code, "adaptive_admin_level": level, "areas": len(areas), "cities": len(cities), "cities_with_parent": sum(bool(item.get("parent_area_id")) for item in cities)}


def load_json(url: str, timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any]:
    request = Request(url, headers={"User-Agent": "IPIntel-Geography/1.0"})
    with urlopen(request, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("geography source must return a JSON object")
    return payload


def geoboundaries_payload(iso3: str, admin_level: int, timeout: float = DEFAULT_TIMEOUT) -> tuple[dict[str, Any], dict[str, Any]]:
    """Resolve metadata, then reuse a matching validated GeoJSON cache."""
    metadata_url = f"https://www.geoboundaries.org/api/current/gbOpen/{iso3.upper()}/ADM{admin_level}/"
    metadata = load_json(metadata_url, timeout)
    download_url = metadata.get("gjDownloadURL")
    if not download_url:
        raise ValueError(f"geoBoundaries ADM{admin_level} has no GeoJSON URL for {iso3}")
    cache_dir = GEOBOUNDARIES_CACHE_DIR / iso3.upper()
    payload_path, metadata_path = cache_dir / f"ADM{admin_level}.json", cache_dir / f"ADM{admin_level}.meta.json"
    cache_metadata = {}
    try:
        cache_metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        if (payload_path.exists() and cache_metadata.get("download_url") == download_url
                and cache_metadata.get("build_date") == metadata.get("buildDate")):
            payload = json.loads(payload_path.read_text(encoding="utf-8"))
            if isinstance(payload, dict) and cache_metadata.get("sha256") == hashlib.sha256(payload_path.read_bytes()).hexdigest():
                return payload, metadata
    except (OSError, ValueError, json.JSONDecodeError):
        pass
    payload = load_json(download_url, timeout)
    if not isinstance(payload, dict):
        raise ValueError(f"geoBoundaries ADM{admin_level} payload is not an object for {iso3}")
    cache_dir.mkdir(parents=True, exist_ok=True)
    temporary = payload_path.with_suffix(".tmp")
    temporary.write_text(json.dumps(payload), encoding="utf-8")
    os.replace(temporary, payload_path)
    metadata_path.write_text(json.dumps({
        "download_url": download_url, "build_date": metadata.get("buildDate"),
        "sha256": hashlib.sha256(payload_path.read_bytes()).hexdigest(),
    }), encoding="utf-8")
    return payload, metadata


def refresh_country(repo: MarketRepository, country_code: str, iso3: str, cities: list[dict[str, Any]],
                    timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """Fetch and persist one country, with durable job status around source work."""
    job_key = f"geography:{country_code}"
    now = datetime.now(timezone.utc).isoformat()
    repo.upsert_job_state({"job_key": job_key, "source": "ghsl+geoboundaries", "country_code": country_code,
                           "status": "downloading", "current_step": "cities_and_boundaries", "started_at": now,
                           "last_heartbeat_at": now})
    try:
        adm1_payload, adm1_meta = geoboundaries_payload(iso3, 1, timeout)
        try:
            adm2_payload, adm2_meta = geoboundaries_payload(iso3, 2, timeout)
        except HTTPError as error:
            if error.code != 404:
                raise
            adm2_payload, adm2_meta = {"type": "FeatureCollection", "features": []}, {}
        adm1 = normalize_boundaries(adm1_payload, country_code, 1)
        adm2 = normalize_boundaries(adm2_payload, country_code, 2)
        result = persist_country(repo, country_code, cities, adm1, adm2,
                               source_version=f"ghsl:{os.getenv('GHSL_SOURCE_VERSION', 'configured')}|gb:{(adm2_meta or adm1_meta).get('buildDate', 'unknown')}")
        completed = datetime.now(timezone.utc).isoformat()
        repo.upsert_job_state({"job_key": job_key, "source": "ghsl+geoboundaries", "country_code": country_code,
                               "status": "done", "current_step": f"adm{result['adaptive_admin_level']}",
                               "source_version": str(adm2_meta.get("buildDate") or adm1_meta.get("buildDate") or "unknown"),
                               "started_at": now, "last_heartbeat_at": completed, "completed_at": completed})
        return result
    except Exception as error:
        failed = datetime.now(timezone.utc).isoformat()
        repo.upsert_job_state({"job_key": job_key, "source": "ghsl+geoboundaries", "country_code": country_code,
                               "status": "failed", "current_step": "source_or_validation", "last_error": type(error).__name__,
                               "started_at": now, "last_heartbeat_at": failed})
        raise


def _download_global_archive(url: str, path: Path, timeout: float = DEFAULT_TIMEOUT) -> Path:
    if path.exists() and zipfile.is_zipfile(path):
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        request = Request(url, headers={"User-Agent": "IPIntel-Geography/1.0"})
        with urlopen(request, timeout=timeout) as response, os.fdopen(fd, "wb") as output:
            while chunk := response.read(1024 * 1024):
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        if not zipfile.is_zipfile(temporary):
            raise ValueError("GHSL global download is not a ZIP archive")
        os.replace(temporary, path)
        return path
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _field(row: dict[str, Any], names: tuple[str, ...]) -> Any:
    normalized = {str(key).strip().lower(): value for key, value in row.items()}
    for name in names:
        if name.lower() in normalized and normalized[name.lower()] not in (None, ""):
            return normalized[name.lower()]
    return None


def _city_from_row(row: dict[str, Any], country_code: str, source_id: str) -> dict[str, Any] | None:
    iso3 = str(_field(row, ("SC_CNT_GAD_2025", "SC_CNT_GAD_2020", "iso3", "country_iso3", "country_code")) or "").upper()
    name = _field(row, ("SC_UCN_MAI_2025", "SC_UCN_MAI_2020", "city_name", "name", "uc_name"))
    lat = _number(_field(row, ("latitude", "lat", "centroid_lat", "y_lat")))
    lon = _number(_field(row, ("longitude", "lon", "centroid_lon", "x_lon")))
    if iso3 and iso3 != country_code.upper() and iso3 != str(country_code).upper():
        # Country filtering is performed by ISO3 in the caller; tolerate ISO2-only fixtures.
        pass
    if not name or lat is None or lon is None:
        return None
    return {"area_id": f"{country_code}:CITY:{source_id}", "country_code": country_code,
            "name": str(name), "area_type": "city", "admin_level": None,
            "granularity_class": "normal", "source": "ghsl", "source_id": source_id,
            "centroid_lat": lat, "centroid_lon": lon,
            "geometry_ref": {"source": "ghsl", "source_id": source_id}}


def _cities_from_csv(handle: io.TextIOBase, country_code: str, iso3: str) -> list[dict[str, Any]]:
    result = []
    for index, row in enumerate(csv.DictReader(handle)):
        row_iso3 = str(_field(row, ("SC_CNT_GAD_2025", "SC_CNT_GAD_2020", "iso3", "country_iso3")) or "").upper()
        if row_iso3 and row_iso3 != iso3.upper():
            continue
        city = _city_from_row(row, country_code, str(_field(row, ("ID_UC_G0", "id", "id_uc")) or index))
        if city:
            result.append(city)
    return result


def _wkb_point(blob: bytes) -> tuple[float, float] | None:
    if not blob:
        return None
    offset = 0
    if blob[:2] == b"GP":
        flags = blob[3]
        envelope = (flags >> 1) & 7
        offset = 8 + {0: 0, 1: 32, 2: 48, 3: 48, 4: 64}.get(envelope, 0)
    if len(blob) < offset + 21:
        return None
    endian = "<" if blob[offset] == 1 else ">"
    geom_type = struct.unpack_from(endian + "I", blob, offset + 1)[0] & 0x0FFFFFFF
    if geom_type != 1:
        return None
    return struct.unpack_from(endian + "dd", blob, offset + 5)[1], struct.unpack_from(endian + "dd", blob, offset + 5)[0]


def _country_names(iso3: str) -> set[str]:
    country = pycountry.countries.get(alpha_3=iso3.upper())
    if not country:
        return {iso3.upper()}
    names = {country.name}
    official = getattr(country, "official_name", None)
    if official:
        names.add(official)
    names.update({"Vietnam"} if iso3.upper() == "VNM" else set())
    return {" ".join(name.casefold().split()) for name in names}


def _mollweide_to_wgs84(x: float, y: float) -> tuple[float, float]:
    """Convert GHSL UCDB World Mollweide EPSG:54009 coordinates to lat/lon."""
    radius = 6371007.181
    theta = math.asin(max(-1.0, min(1.0, y / (radius * math.sqrt(2)))))
    longitude = math.pi * x / (2 * math.sqrt(2) * radius * math.cos(theta)) if abs(math.cos(theta)) > 1e-12 else 0.0
    latitude = math.asin(max(-1.0, min(1.0, (2 * theta + math.sin(2 * theta)) / math.pi)))
    return math.degrees(latitude), math.degrees(longitude)


def _cities_from_gpkg(path: Path, country_code: str, iso3: str) -> list[dict[str, Any]]:
    result = []
    country_names = _country_names(iso3)
    with sqlite3.connect(path) as conn:
        tables = conn.execute("SELECT table_name, column_name FROM gpkg_geometry_columns").fetchall()
        table_names = {table for table, _ in tables}
        if "UC_centroids" in table_names:
            attribute_table = next((table for table in table_names if "GENERAL_CHARACTERISTICS" in table), None)
            if attribute_table:
                rows = conn.execute(f'''SELECT c.geom, c.ID_UC_G0, a.GC_UCN_MAI_2025, a.GC_CNT_GAD_2025
                                        FROM "UC_centroids" c LEFT JOIN "{attribute_table}" a
                                        ON c.ID_UC_G0 = a.ID_UC_G0''').fetchall()
                for index, blob, city_id, name, row_iso3 in ((i, *row) for i, row in enumerate(rows)):
                    source_country = " ".join(str(row_iso3 or "").casefold().split())
                    if source_country not in country_names and source_country != iso3.casefold():
                        continue
                    point = _wkb_point(blob)
                    if not point:
                        continue
                    raw_y, raw_x = point
                    lat, lon = _mollweide_to_wgs84(raw_x, raw_y)
                    result.append({"area_id": f"{country_code}:CITY:{city_id or index}", "country_code": country_code,
                                   "name": str(name or city_id or index), "area_type": "city", "admin_level": None,
                                   "granularity_class": "normal", "source": "ghsl", "source_id": str(city_id or index),
                                   "centroid_lat": lat, "centroid_lon": lon,
                                   "geometry_ref": {"source": "ghsl", "source_id": str(city_id or index), "crs": "EPSG:54009"}})
                return result
        for table, geometry_column in tables:
            columns = [row[1] for row in conn.execute(f'PRAGMA table_info("{table}")').fetchall()]
            rows = conn.execute(f'SELECT * FROM "{table}"').fetchall()
            for index, values in enumerate(rows):
                row = dict(zip(columns, values))
                row_iso3 = str(_field(row, ("SC_CNT_GAD_2025", "SC_CNT_GAD_2020", "iso3", "country_iso3")) or "").upper()
                if row_iso3 and row_iso3 != iso3.upper():
                    continue
                point = _wkb_point(row.get(geometry_column))
                if not point:
                    continue
                row["latitude"], row["longitude"] = point
                city = _city_from_row(row, country_code, str(_field(row, ("ID_UC_G0", "id", "id_uc")) or index))
                if city:
                    result.append(city)
    return result


def _global_cities(path: Path, country_code: str, iso3: str) -> list[dict[str, Any]]:
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        gpkg_names = [name for name in names if name.lower().endswith(".gpkg") and "ucdb" in name.lower()]
        if gpkg_names:
            extracted = GHSL_CACHE_DIR / Path(gpkg_names[0]).name
            if not extracted.exists():
                with archive.open(gpkg_names[0]) as source, extracted.open("wb") as target:
                    shutil.copyfileobj(source, target, length=1024 * 1024)
            return _cities_from_gpkg(extracted, country_code, iso3)
        csv_names = [name for name in names if name.lower().endswith(".csv") and "ucdb" in name.lower()]
        if not csv_names:
            raise ValueError("GHSL archive contains no UCDB CSV or GeoPackage")
        with archive.open(csv_names[0]) as source:
            return _cities_from_csv(io.TextIOWrapper(source, encoding="utf-8-sig", errors="replace"), country_code, iso3)


def refresh_all(repo: MarketRepository, global_url: str, timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """Resume canonical primary markets; one country failure does not erase good rows."""
    by_code = {item["country_code"]: item for item in catalog_rows() if item["primary_market"] and item["active"]}
    archive = _download_global_archive(global_url, GHSL_ARCHIVE_PATH, timeout)
    results, failures, skipped = [], [], []
    force = os.getenv("GEOGRAPHY_FORCE_REFRESH", "false").strip().lower() in {"1", "true", "yes", "on"}
    pending = []
    for country_code, item in by_code.items():
        if not force:
            state = repo.get_job_state(f"geography:{country_code}")
            if (state and state.get("status") == "done"
                    and _boundary_artifacts_available(str(item["iso3_code"]), state)):
                skipped.append(country_code)
                continue
        pending.append((country_code, item))

    try:
        workers = max(1, min(4, int(os.getenv("GEOGRAPHY_WORKERS", "2"))))
    except ValueError:
        workers = 2

    def refresh_item(country_code: str, item: dict[str, Any]) -> dict[str, Any]:
        cities = _global_cities(archive, country_code, str(item["iso3_code"]))
        return refresh_country(repo, country_code, str(item["iso3_code"]), cities, timeout)

    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="geography") as executor:
        futures = {executor.submit(refresh_item, country_code, item): country_code for country_code, item in pending}
        for future in as_completed(futures):
            country_code = futures[future]
            try:
                results.append(future.result())
            except Exception as error:
                failures.append({"country_code": country_code, "error": type(error).__name__})
    return {"status": "completed" if not failures else "partial", "countries": len(by_code),
            "completed": len(results), "skipped_done": len(skipped), "failed": failures,
            "areas": sum(item["areas"] for item in results), "workers": workers}


def catalog_country_codes() -> list[str]:
    return [str(item["country_code"]) for item in catalog_rows() if item["primary_market"] and item["active"]]


def main() -> None:
    global_url = os.getenv("GHSL_CITY_GLOBAL_URL")
    if not global_url:
        raise SystemExit("GHSL_CITY_GLOBAL_URL is required; no geography source was contacted")
    try:
        result = refresh_all(MarketRepository(), global_url, float(os.getenv("GEOGRAPHY_REQUEST_TIMEOUT", DEFAULT_TIMEOUT)))
        print(json.dumps(result, indent=2))
    finally:
        close_pool()


if __name__ == "__main__":
    main()
