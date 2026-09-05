"""Scheduler-owned H3 to geography area membership refresh."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Iterable

from app.config.settings import DATA_DIR
from app.db.market_repository import MarketRepository
from scripts.geo.geography_foundation import _bbox_candidates, _inside, normalize_boundaries
from scripts.geo.osm_h3_pilot import PRIORITY_COUNTRIES

AREA_MEMBERSHIP_VERSION = "phase6b2-membership-v4"


def h3_centroid(cell_id: str) -> tuple[float, float]:
    try:
        import h3
    except ImportError as exc:
        raise RuntimeError("H3 is required for area membership") from exc
    if hasattr(h3, "cell_to_latlng"):
        lat, lon = h3.cell_to_latlng(cell_id)
    else:
        lat, lon = h3.h3_to_geo(cell_id)
    return float(lat), float(lon)


def _hash_files(paths: Iterable[Path]) -> str:
    digest = hashlib.sha256()
    for path in paths:
        digest.update(str(path).encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def _load_boundaries(iso3: str, country_code: str, cache_dir: Path,
                     admin_levels: set[int]) -> tuple[list[dict[str, Any]], str]:
    paths = [cache_dir / iso3 / f"ADM{level}.json" for level in sorted(admin_levels, reverse=True)]
    existing = [path for path in paths if path.exists()]
    if not existing:
        raise FileNotFoundError(f"boundary cache missing for {iso3}")
    boundaries = []
    for path in existing:
        level = int(path.stem[-1])
        payload = json.loads(path.read_text(encoding="utf-8"))
        boundaries.extend(normalize_boundaries(payload, country_code, level))
    return boundaries, _hash_files(existing)


def map_point_to_area(point: tuple[float, float], boundaries: list[dict[str, Any]]) -> str | None:
    for area in sorted(_bbox_candidates(boundaries, point), key=lambda item: -int(item.get("admin_level") or 0)):
        if _inside(area["_feature"], point):
            return area["area_id"]
    return None


def refresh_area_membership(repo: MarketRepository, countries: Iterable[str] | None = None) -> dict[str, Any]:
    selected = [str(code).strip().upper() for code in (countries or os.getenv("OSM_COUNTRIES", ",".join(PRIORITY_COUNTRIES)).split(",")) if str(code).strip()]
    cache_dir = Path(os.getenv("GEOGRAPHY_CACHE_DIR", str(DATA_DIR / "geography" / "geoboundaries")))
    reports = {}
    for country in selected:
        job_key = f"area_membership:{country}"
        try:
            iso3 = repo.country_iso3(country)
            if not iso3:
                raise RuntimeError("ISO3 country identity is missing")
            admin_levels = repo.administrative_levels(country)
            boundaries, source_hash = _load_boundaries(iso3, country, cache_dir, admin_levels)
            previous = repo.get_job_state(job_key)
            if previous and previous.get("status") == "done" and previous.get("source_hash") == source_hash and previous.get("source_version") == AREA_MEMBERSHIP_VERSION:
                reports[country] = {"status": "skipped_unchanged", "source_hash": source_hash}
                continue
            cells = repo.list_local_cells_for_mapping(country)
            updates = []
            for cell in cells:
                area_id = map_point_to_area(h3_centroid(cell["h3_cell_id"]), boundaries)
                # Include an explicit NULL for cells whose previous membership
                # is invalid or whose centroid is outside the persisted level.
                # Otherwise a stale dangling ID would survive a remap forever.
                updates.append({**cell, "area_id": area_id})
            repo.upsert_job_state({"job_key": job_key, "source": "area_membership", "country_code": country,
                                   "status": "processing", "current_step": "mapping", "source_version": AREA_MEMBERSHIP_VERSION,
                                   "source_hash": source_hash})
            updated = repo.update_local_area_membership(updates)
            repo.upsert_job_state({"job_key": job_key, "source": "area_membership", "country_code": country,
                                   "status": "done", "current_step": "done", "source_version": AREA_MEMBERSHIP_VERSION,
                                   "source_hash": source_hash})
            reports[country] = {"status": "updated", "cells_seen": len(cells), "cells_mapped": updated,
                                "cells_unmapped": len(cells) - updated, "source_hash": source_hash}
        except Exception as exc:
            repo.upsert_job_state({"job_key": job_key, "source": "area_membership", "country_code": country,
                                   "status": "failed", "current_step": "failed", "source_version": AREA_MEMBERSHIP_VERSION,
                                   "last_error": f"{type(exc).__name__}: {exc}"[:240]})
            reports[country] = {"status": "failed", "error": type(exc).__name__, "message": str(exc)[:240]}
    failed = [country for country, result in reports.items() if result["status"] == "failed"]
    return {"status": "partial" if failed else "completed", "countries": reports, "failed": failed}
