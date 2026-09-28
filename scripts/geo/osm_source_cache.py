"""Manage bounded OSM source downloads, cache inspection, and preflight."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any, Iterable

import requests

from app.config.market_sources import resolve_osm_source


def download_snapshot(url: str, destination: Path, timeout: float = 60.0) -> tuple[Path, int]:
    """Download atomically, resuming an interrupted ``.part`` when supported."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() and destination.stat().st_size:
        return destination, 0
    temporary = destination.with_suffix(destination.suffix + ".part")
    offset = temporary.stat().st_size if temporary.exists() else 0
    headers = {"User-Agent": "IPIntel-OSM-Pilot/1.0"}
    if offset:
        headers["Range"] = f"bytes={offset}-"
    bytes_written = 0
    with requests.get(url, stream=True, timeout=timeout, headers=headers) as response:
        if response.status_code == 416:
            raise RuntimeError("download range is unsatisfiable for existing partial source")
        response.raise_for_status()
        resumed = bool(offset and response.status_code == 206)
        if resumed:
            content_range = response.headers.get("Content-Range", "")
            if not content_range.startswith(f"bytes {offset}-"):
                raise RuntimeError("server returned an invalid content range for partial source")
        mode = "ab" if resumed else "wb"
        with temporary.open(mode) as output:
            for chunk in response.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    output.write(chunk)
                    bytes_written += len(chunk)
    temporary.replace(destination)
    return destination, bytes_written


def sha256_file(path: Path) -> str:
    """Calculate a file's SHA-256 digest in bounded-memory chunks."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def remove_superseded_sources(source_dir: Path, country: str, current: Path) -> list[str]:
    """Delete older PBF snapshots for a country while preserving the current file."""
    removed = []
    for candidate in source_dir.glob(f"{country.lower()}*.osm.pbf"):
        if candidate != current and candidate.is_file():
            candidate.unlink()
            removed.append(str(candidate))
    return removed


def cache_bytes(path: Path) -> int:
    """Sum the size of all regular files below an existing cache directory."""
    return sum(item.stat().st_size for item in path.rglob("*") if item.is_file()) if path.exists() else 0


def cache_retention_plan(cache_dir: Path, active_countries: Iterable[str],
                         busy_countries: Iterable[str] = (), target_bytes: int = 3 * 1024 ** 3) -> dict[str, Any]:
    """Plan deterministic, fail-closed eviction of reconstructible OSM cache files."""
    cache_dir = cache_dir.resolve()
    active = {str(country).strip().upper() for country in active_countries}
    busy = {str(country).strip().upper() for country in busy_countries}
    current = cache_bytes(cache_dir)
    eligible: list[dict[str, Any]] = []
    protected: list[dict[str, Any]] = []
    source_dir = cache_dir / "sources"
    candidate_dir = cache_dir / "candidates"
    for path in sorted(cache_dir.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(cache_dir)
        if path.suffix == ".part" or path.name.endswith((".partial", ".tmp", ".lock")):
            protected.append({"path": str(relative), "bytes": path.stat().st_size, "reason": "incomplete_or_lock_file"})
            continue
        if candidate_dir in path.parents:
            eligible.append({"path": str(relative), "bytes": path.stat().st_size, "reason": "completed_candidate"})
            continue
        if source_dir in path.parents and path.suffix == ".pbf":
            country = path.stem.split(".", 1)[0].upper()
            if country in active and country not in busy:
                eligible.append({"path": str(relative), "bytes": path.stat().st_size,
                                 "reason": "active_snapshot_provenance_persisted"})
            else:
                reason = "source_in_use" if country in busy else "no_verified_active_snapshot"
                protected.append({"path": str(relative), "bytes": path.stat().st_size, "reason": reason})
            continue
        protected.append({"path": str(relative), "bytes": path.stat().st_size,
                          "reason": "not_a_reconstructible_osm_source"})
    needed = max(0, current - max(0, target_bytes))
    selected: list[dict[str, Any]] = []
    reclaimed = 0
    for item in sorted(eligible, key=lambda value: (-value["bytes"], value["path"])):
        if reclaimed >= needed:
            break
        selected.append(item)
        reclaimed += item["bytes"]
    return {
        "status": "ready" if reclaimed >= needed else "blocked_insufficient_eligible_cache",
        "cache_dir": str(cache_dir), "cache_before_bytes": current,
        "target_bytes": max(0, target_bytes), "required_reclaim_bytes": needed,
        "eligible_bytes": sum(item["bytes"] for item in eligible),
        "selected_bytes": reclaimed, "projected_after_bytes": current - reclaimed,
        "deletions": selected, "protected": protected,
    }


def apply_cache_retention(plan: dict[str, Any]) -> dict[str, Any]:
    """Apply only the exact validated paths from a retention plan."""
    if plan.get("status") != "ready":
        raise RuntimeError(f"retention plan is not applicable: {plan.get('status')}")
    cache_dir = Path(plan["cache_dir"]).resolve()
    removed = []
    for item in plan["deletions"]:
        path = (cache_dir / item["path"]).resolve()
        if cache_dir not in path.parents or not path.is_file():
            raise RuntimeError(f"retention target changed or escaped cache directory: {path}")
        path.unlink()
        removed.append({"path": item["path"], "bytes": item["bytes"]})
    return {"status": "applied", "removed": removed, "cache_after_bytes": cache_bytes(cache_dir)}


def _disk_limit_bytes(name: str, default_gib: float) -> int:
    """Read a disk limit in GiB and fall back when configuration is invalid."""
    try:
        return max(0, int(float(os.getenv(name, str(default_gib))) * 1024 ** 3))
    except (TypeError, ValueError):
        return int(default_gib * 1024 ** 3)


def source_size(url: str, timeout: float = 30.0) -> int | None:
    """Read an OSM source size with HEAD and reject HTML endpoints."""
    response = requests.head(url, allow_redirects=True, timeout=timeout,
                             headers={"User-Agent": "IPIntel-OSM-Scale/1.0"})
    response.raise_for_status()
    content_type = response.headers.get("content-type", "").lower()
    if "text/html" in content_type:
        raise ValueError(f"OSM source endpoint returned HTML, not PBF: {response.url}")
    value = response.headers.get("content-length")
    return int(value) if value and value.isdigit() else None


def preflight_osm_source(country: str, cache_dir: Path) -> dict[str, Any]:
    """Resolve one registered source and estimate disk impact using HEAD only."""
    country = str(country).strip().upper()
    source_url, source_kind = resolve_osm_source(country)
    source_path = cache_dir / "sources" / f"{country.lower()}.osm.pbf"
    disk_before = cache_bytes(cache_dir)
    existing_bytes = source_path.stat().st_size if source_path.exists() else 0
    content_length = source_size(source_url, float(os.getenv("OSM_HEAD_TIMEOUT", "10")))
    estimated_download = max(0, (content_length or 0) - existing_bytes)
    soft_limit = _disk_limit_bytes("OSM_CACHE_SOFT_LIMIT_GIB", 9.0)
    hard_limit = _disk_limit_bytes("OSM_CACHE_HARD_LIMIT_GIB", 10.0)
    projected = disk_before + estimated_download
    if content_length is None:
        status = "resolved_size_unavailable"
        retention_action = "capture_size_before_download"
    elif projected > hard_limit:
        status = "blocked_disk_hard_limit"
        retention_action = "cleanup_candidates_and_superseded_sources_before_download"
    elif projected > soft_limit:
        status = "ready_after_retention"
        retention_action = "cleanup_candidates_and_superseded_sources_before_download"
    else:
        status = "ready"
        retention_action = "retain_current_source"
    return {
        "country": country,
        "source_url": source_url,
        "source_kind": source_kind,
        "source_resolved": True,
        "content_length_bytes": content_length,
        "disk_before_bytes": disk_before,
        "estimated_download_bytes": estimated_download,
        "projected_disk_bytes": projected,
        "soft_limit_bytes": soft_limit,
        "hard_limit_bytes": hard_limit,
        "retention_action": retention_action,
        "status": status,
    }


def preflight_osm_sources(countries: Iterable[str], cache_dir: Path) -> dict[str, Any]:
    """Run source/disk preflight without creating files or touching PostgreSQL."""
    reports: dict[str, Any] = {}
    for raw_country in countries:
        country = str(raw_country).strip().upper()
        try:
            reports[country] = preflight_osm_source(country, cache_dir)
        except Exception as exc:
            reports[country] = {
                "country": country,
                "source_resolved": False,
                "status": "blocked_source",
                "error": f"{type(exc).__name__}: {exc}",
            }
    blocked = [country for country, item in reports.items() if item["status"].startswith("blocked")]
    return {"status": "blocked" if blocked else "ready", "countries": reports, "blocked": blocked}
