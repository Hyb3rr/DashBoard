"""Scheduler-owned Phase 5B auxiliary local evidence refresh."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Iterable

from app.config.settings import DATA_DIR
from app.db.market_repository import MarketRepository
from scripts.geo.osm_h3_pilot import PRIORITY_COUNTRIES, SCALE_SOURCE_URLS, _cell, download_snapshot, production_resolution, sha256_file

AUXILIARY_VERSION = "phase5b-auxiliary-v1"
AUXILIARY_TAGS = (
    "nwr/landuse=industrial", "nwr/industrial=*")
AUXILIARY_ACCESS_TAGS = (
    "nwr/highway=motorway", "nwr/highway=trunk", "nwr/highway=primary",
    "nwr/railway=*")
AUXILIARY_PORT_TAGS = ("nwr/natural=harbour", "nwr/harbour=yes", "nwr/industrial=port")
AUXILIARY_AIRPORT_TAGS = ("nwr/aeroway=aerodrome", "nwr/aeroway=terminal")


def _source_candidates(country: str, cache_dir: Path) -> list[Path]:
    configured = os.getenv(f"OSM_PBF_PATH_{country}")
    return [Path(configured)] if configured else [
        cache_dir / "sources" / f"{country.lower()}.osm.pbf",
        DATA_DIR / "geography" / "osm" / "candidates" / "sources" / f"{country.lower()}.osm.pbf",
        DATA_DIR / "geography" / "osm" / f"{country.lower()}-pilot.osm.pbf",
    ]


def resolve_source(country: str, cache_dir: Path) -> Path | None:
    return next((path for path in _source_candidates(country, cache_dir) if path.exists() and path.stat().st_size), None)


def _native_auxiliary_filter(source: Path, candidate: Path, budget_seconds: float) -> None:
    binary = os.getenv("OSMIUM_BIN") or shutil.which("osmium")
    if not binary:
        raise RuntimeError("native osmium CLI is required for Phase 5B")
    candidate.parent.mkdir(parents=True, exist_ok=True)
    temporary = candidate.with_name(f"{candidate.stem}.part{candidate.suffix}")
    command = [binary, "tags-filter", "--overwrite", "-o", str(temporary), str(source),
               *AUXILIARY_TAGS, *AUXILIARY_ACCESS_TAGS, *AUXILIARY_PORT_TAGS, *AUXILIARY_AIRPORT_TAGS]
    try:
        subprocess.run(command, check=True, capture_output=True, text=True, timeout=budget_seconds)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"auxiliary native filter budget exceeded ({budget_seconds:.0f}s)") from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"auxiliary native filter failed: {(exc.stderr or exc.stdout or '').strip()[:200]}") from exc
    temporary.replace(candidate)


def _points(entity: Any) -> list[tuple[float, float]]:
    location = getattr(entity, "location", None)
    if location and getattr(location, "valid", lambda: False)():
        return [(float(location.lat), float(location.lon))]
    nodes = getattr(entity, "nodes", ())
    points = [(float(node.lat), float(node.lon)) for node in nodes if getattr(node, "valid", lambda: False)()]
    return [(sum(lat for lat, _ in points) / len(points), sum(lon for _, lon in points) / len(points))] if points else []


def scan_auxiliary(candidate: Path, country: str, source_hash: str) -> list[dict[str, Any]]:
    try:
        import osmium
    except ImportError as exc:
        raise RuntimeError("PyOsmium is required for Phase 5B") from exc
    resolution = production_resolution()
    cells: dict[str, dict[str, int]] = {}

    class Handler(osmium.SimpleHandler):
        def visit(self, entity: Any) -> None:
            tags = dict(entity.tags)
            points = _points(entity)
            if not points:
                return
            cell = _cell(*points[0], resolution)
            counts = cells.setdefault(cell, {"industrial_land_count": 0, "motorway_count": 0,
                "primary_road_count": 0, "railway_count": 0, "port_count": 0,
                "airport_count": 0, "access_observation_count": 0})
            if tags.get("landuse") == "industrial" or "industrial" in tags:
                counts["industrial_land_count"] += 1
            highway = tags.get("highway")
            if highway in {"motorway", "trunk"}:
                counts["motorway_count"] += 1
                counts["access_observation_count"] += 1
            if highway == "primary":
                counts["primary_road_count"] += 1
                counts["access_observation_count"] += 1
            if "railway" in tags:
                counts["railway_count"] += 1
                counts["access_observation_count"] += 1
            if tags.get("natural") == "harbour" or tags.get("harbour") == "yes" or tags.get("industrial") == "port":
                counts["port_count"] += 1
                counts["access_observation_count"] += 1
            if tags.get("aeroway") in {"aerodrome", "terminal"}:
                counts["airport_count"] += 1
                counts["access_observation_count"] += 1

        node = visit
        way = visit
        relation = visit

    Handler().apply_file(str(candidate), locations=True, idx="flex_mem")
    rows = []
    for cell, counts in cells.items():
        for track in ("woodworking", "metal_fabrication"):
            rows.append({"country_code": country, "h3_cell_id": cell, "h3_resolution": resolution,
                         "track": track, "source": "osm_auxiliary", "source_version": AUXILIARY_VERSION,
                         "source_hash": source_hash, **counts})
    return rows


def refresh_local_evidence(repo: MarketRepository, countries: Iterable[str] | None = None) -> dict[str, Any]:
    selected = [str(code).strip().upper() for code in (countries or os.getenv("OSM_COUNTRIES", ",".join(PRIORITY_COUNTRIES)).split(",")) if str(code).strip()]
    cache_dir = Path(os.getenv("OSM_CACHE_DIR", str(DATA_DIR / "geography" / "osm" / "scale")))
    candidate_dir = cache_dir / "auxiliary-candidates"
    reports: dict[str, Any] = {}
    for country in selected:
        started = time.perf_counter()
        job_key = f"osm_aux:{country}"
        try:
            active = repo.active_osm_snapshot(country)
            if not active:
                raise RuntimeError("active OSM snapshot is required")
            previous = repo.get_job_state(job_key)
            if (previous and previous.get("status") == "done"
                    and previous.get("source_hash") == active.get("source_hash")):
                reports[country] = {"status": "skipped_unchanged", "source_hash": active["source_hash"]}
                continue
            source = resolve_source(country, cache_dir)
            if not source:
                destination = cache_dir / "sources" / f"{country.lower()}.osm.pbf"
                source, _ = download_snapshot(SCALE_SOURCE_URLS[country], destination, float(os.getenv("OSM_DOWNLOAD_TIMEOUT", "120")))
            source_hash = sha256_file(source)
            if source_hash != active["source_hash"]:
                raise RuntimeError("source hash does not match active OSM snapshot")
            if previous and previous.get("status") == "done" and previous.get("source_hash") == source_hash:
                reports[country] = {"status": "skipped_unchanged", "source_hash": source_hash}
                continue
            repo.upsert_job_state({"job_key": job_key, "source": "osm_aux", "country_code": country,
                                   "status": "processing", "current_step": "prefiltering", "source_version": AUXILIARY_VERSION,
                                   "source_hash": source_hash})
            candidate = candidate_dir / f"{country.lower()}-{AUXILIARY_VERSION}.osm.pbf"
            _native_auxiliary_filter(source, candidate, float(os.getenv("OSM_AUXILIARY_BUDGET_SECONDS", "900")))
            rows = scan_auxiliary(candidate, country, source_hash)
            snapshot_id = active["snapshot_id"]
            for row in rows:
                row["snapshot_id"] = snapshot_id
            persisted = repo.upsert_auxiliary_evidence(rows)
            if candidate.exists():
                candidate.unlink()
            repo.upsert_job_state({"job_key": job_key, "source": "osm_aux", "country_code": country,
                                   "status": "done", "current_step": "done", "source_version": AUXILIARY_VERSION,
                                   "source_hash": source_hash})
            reports[country] = {"status": "updated", "rows": persisted, "source_hash": source_hash,
                                "elapsed_seconds": time.perf_counter() - started}
        except Exception as exc:
            repo.upsert_job_state({"job_key": job_key, "source": "osm_aux", "country_code": country,
                                   "status": "failed", "current_step": "failed", "source_version": AUXILIARY_VERSION,
                                   "last_error": f"{type(exc).__name__}: {exc}"[:240]})
            reports[country] = {"status": "failed", "error": type(exc).__name__, "message": str(exc)[:240]}
    failed = [country for country, item in reports.items() if item["status"] == "failed"]
    return {"status": "partial" if failed else "completed", "countries": reports, "failed": failed}
