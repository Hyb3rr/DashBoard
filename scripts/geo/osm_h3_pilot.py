"""Phase 4A OSM/H3 pilot.

Offline-only measurement tool. It never runs from FastAPI, never writes the
production database, and never computes opportunity scores.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import resource
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import requests

from app.config.market_sources import (
    OSM_SOURCE_URLS,
    PRIORITY_SOURCE_URLS,
    SUPPORTED_OSM_COUNTRIES,
    WAVE_1_COUNTRIES,
    resolve_osm_source,
)

PILOTS = ("SG", "VN", "DE")
SCALE_COUNTRIES = ("SG", "VN", "DE", "TH", "MY", "ID", "PH", "KR", "PL", "IT")
PRIORITY_COUNTRIES = SCALE_COUNTRIES
SCALE_SOURCE_URLS = {country: OSM_SOURCE_URLS[country] for country in SCALE_COUNTRIES}
DEFAULT_RESOLUTIONS = (7, 8)
FILTER_VERSION = "phase4a-sector-tags-v1"
CLASSIFICATION_VERSION = FILTER_VERSION
DEFAULT_OSM_URLS = dict(PRIORITY_SOURCE_URLS)
RETENTION_BUSY_STATUSES = frozenset({"downloading", "prefiltering", "processing", "persisting", "validating"})


def production_resolution() -> int:
    value = int(os.getenv("MARKET_H3_RESOLUTION", "7"))
    if value != 7:
        raise ValueError("Phase 4B production H3 resolution must be 7")
    return value
SECTOR_TAGS: dict[str, set[tuple[str, str]]] = {
    "WOODWORKING": {("craft", "carpenter"), ("craft", "sawmill"), ("industrial", "sawmill"), ("man_made", "sawmill")},
    "METAL_FABRICATION": {("craft", "metal_construction"), ("industrial", "metalworking"), ("industrial", "steelmaking"), ("man_made", "works")},
}


@dataclass
class PilotMetrics:
    country: str
    source_path: str
    pbf_bytes: int = 0
    candidate_pbf_bytes: int = 0
    native_filter_seconds: float = 0.0
    downloaded_bytes: int = 0
    scan_seconds: float = 0.0
    filter_seconds: float = 0.0
    geometry_seconds: float = 0.0
    h3_seconds: dict[str, float] = field(default_factory=dict)
    entities_seen: int = 0
    candidates_seen: int = 0
    retained_observations: int = 0
    rejected_by_tag: int = 0
    h3_cells: dict[str, int] = field(default_factory=dict)
    way_entities: int = 0
    ways_with_geometry: int = 0
    ways_missing_geometry: int = 0
    peak_rss_bytes: int = 0
    source_sha256: str | None = None
    error: str | None = None
    cell_features: dict[str, dict[str, int]] = field(default_factory=dict)

    @property
    def rejection_rate(self) -> float:
        return (self.rejected_by_tag / self.candidates_seen) if self.candidates_seen else 0.0

    def as_dict(self) -> dict[str, Any]:
        result = dict(self.__dict__)
        result["rejection_rate"] = round(self.rejection_rate, 6)
        return result


def _feature_counts(tags: dict[str, str], sector: str) -> dict[str, int]:
    counts = {"industrial_area_count": 0, "works_count": 0, "sawmill_count": 0,
              "furniture_evidence_count": 0, "wood_processing_count": 0,
              "metal_evidence_count": 0, "machinery_evidence_count": 0, "osm_feature_count": 1}
    if tags.get("industrial") == "sawmill" or tags.get("man_made") == "sawmill":
        counts["sawmill_count"] = 1
    if tags.get("man_made") == "works":
        counts["works_count"] = 1
    if sector == "WOODWORKING":
        counts["wood_processing_count"] = 1
    if sector == "METAL_FABRICATION":
        counts["metal_evidence_count"] = 1
    return counts


def _rss_bytes() -> int:
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(value if os.sys.platform == "darwin" else value * 1024)


def classify_tags(tags: dict[str, str] | Iterable[tuple[str, str]]) -> set[str]:
    pairs = set(tags.items()) if isinstance(tags, dict) else set(tags)
    return {sector for sector, rules in SECTOR_TAGS.items() if pairs & rules}


def native_filter_args() -> list[str]:
    """Versioned native filter; referenced nodes remain because -R is absent."""
    return [f"nwr/{key}={value}" for rules in SECTOR_TAGS.values() for key, value in sorted(rules)]


def native_prefilter(path: Path, destination: Path, budget_seconds: float = 600.0) -> dict[str, Any]:
    """Create candidate PBF in native osmium, atomically and with references."""
    binary = os.getenv("OSMIUM_BIN") or shutil.which("osmium")
    if not binary:
        raise RuntimeError("native osmium CLI is required for Phase 4A.1")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f"{destination.stem}.part{destination.suffix}")
    command = [binary, "tags-filter", "--overwrite", "-o", str(temporary), str(path), *native_filter_args()]
    started = time.perf_counter()
    try:
        completed = subprocess.run(command, check=True, capture_output=True, text=True, timeout=budget_seconds)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"native osmium budget exceeded ({budget_seconds:.0f}s)") from exc
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or "native osmium failed").strip()
        raise RuntimeError(f"native osmium failed: {detail}") from exc
    temporary.replace(destination)
    return {
        "filter_version": FILTER_VERSION,
        "command": command,
        "seconds": time.perf_counter() - started,
        "original_bytes": path.stat().st_size,
        "candidate_bytes": destination.stat().st_size,
        "reduction_ratio": 1 - (destination.stat().st_size / path.stat().st_size),
        "stderr": completed.stderr.strip(),
    }


def _cell(lat: float, lon: float, resolution: int) -> str:
    try:
        import h3
    except ImportError as exc:
        raise RuntimeError("H3 pilot requires h3; install project requirements") from exc
    if hasattr(h3, "latlng_to_cell"):
        return str(h3.latlng_to_cell(lat, lon, resolution))
    return str(h3.geo_to_h3(lat, lon, resolution))


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
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def remove_superseded_sources(source_dir: Path, country: str, current: Path) -> list[str]:
    removed = []
    for candidate in source_dir.glob(f"{country.lower()}*.osm.pbf"):
        if candidate != current and candidate.is_file():
            candidate.unlink()
            removed.append(str(candidate))
    return removed


def cache_bytes(path: Path) -> int:
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
        protected.append({"path": str(relative), "bytes": path.stat().st_size, "reason": "not_a_reconstructible_osm_source"})
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
    try:
        return max(0, int(float(os.getenv(name, str(default_gib))) * 1024 ** 3))
    except (TypeError, ValueError):
        return int(default_gib * 1024 ** 3)


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


def percentile(values: list[float], ratio: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int((len(ordered) - 1) * ratio)))
    return ordered[index]


def source_size(url: str, timeout: float = 30.0) -> int | None:
    response = requests.head(url, allow_redirects=True, timeout=timeout, headers={"User-Agent": "IPIntel-OSM-Scale/1.0"})
    response.raise_for_status()
    content_type = response.headers.get("content-type", "").lower()
    if "text/html" in content_type:
        raise ValueError(f"OSM source endpoint returned HTML, not PBF: {response.url}")
    value = response.headers.get("content-length")
    return int(value) if value and value.isdigit() else None


def run_scale_benchmark(countries: Iterable[str] = SCALE_COUNTRIES, cache_dir: Path = Path("data/geography/osm/scale"),
                        disk_budget_bytes: int = 10 * 1024 ** 3, budget_seconds: float = 900.0,
                        retain_sources: bool = True) -> dict[str, Any]:
    """Measure bounded multi-country scale without production persistence."""
    selected = [str(code).upper() for code in countries]
    unknown = sorted(set(selected) - set(SCALE_SOURCE_URLS))
    if unknown:
        raise ValueError(f"scale countries not supported: {unknown}")
    source_dir, candidate_dir = cache_dir / "sources", cache_dir / "candidates"
    source_dir.mkdir(parents=True, exist_ok=True)
    baseline = cache_bytes(cache_dir)
    reports, timings, failures = {}, [], []
    for country in selected:
        url = SCALE_SOURCE_URLS[country]
        started = time.perf_counter()
        try:
            destination = source_dir / f"{country.lower()}.osm.pbf"
            expected = source_size(url, float(os.getenv("OSM_HEAD_TIMEOUT", "10"))) if not destination.exists() else destination.stat().st_size
            if expected and baseline + max(0, expected - (destination.stat().st_size if destination.exists() else 0)) > disk_budget_bytes:
                raise RuntimeError("scale disk budget exceeded before download")
            path, downloaded = download_snapshot(url, destination, float(os.getenv("OSM_DOWNLOAD_TIMEOUT", "120")))
            report = run_native_pipeline(path, country, candidate_dir, (production_resolution(),), budget_seconds)
            elapsed = time.perf_counter() - started
            timings.append(elapsed)
            reports[country] = {key: value for key, value in report.items() if key != "cell_features"}
            reports[country].update({"downloaded_bytes": downloaded, "elapsed_seconds": elapsed,
                                     "cache_bytes": cache_bytes(cache_dir), "raw_feature_rows": len(report.get("cell_features", {}))})
            candidate = Path(report["candidate_path"])
            if candidate.exists():
                candidate.unlink()
        except Exception as exc:
            failures.append(country)
            reports[country] = {"status": "failed", "error": type(exc).__name__, "message": str(exc)[:240],
                                "elapsed_seconds": time.perf_counter() - started}
        if not retain_sources:
            source_path = source_dir / f"{country.lower()}.osm.pbf"
            if source_path.exists():
                source_path.unlink()
    successful = [item for item in reports.values() if item.get("status") != "failed"]
    rows = sum(int(item.get("raw_feature_rows", 0)) for item in successful)
    return {"phase": "4C-A", "status": "partial" if failures else "completed", "countries": reports,
            "failed": failures, "disk_budget_bytes": disk_budget_bytes, "baseline_cache_bytes": baseline,
            "final_cache_bytes": cache_bytes(cache_dir), "wall_seconds": sum(timings),
            "country_wall_p50": percentile(timings, 0.50), "country_wall_p95": percentile(timings, 0.95),
            "measured_raw_feature_rows": rows,
            "rough_193_row_estimate": (rows / len(successful) * 193) if successful else None,
            "retained_sources": retain_sources}


def _entity_tags(entity: Any) -> dict[str, str]:
    tags = getattr(entity, "tags", {})
    return dict(tags) if tags else {}


def _entity_points(entity: Any) -> list[tuple[float, float]]:
    if hasattr(entity, "location") and entity.location.valid():
        return [(float(entity.location.lat), float(entity.location.lon))]
    points = []
    for node in getattr(entity, "nodes", ()):
        location = getattr(node, "location", None)
        if location and location.valid():
            points.append((float(location.lat), float(location.lon)))
    if not points:
        return []
    # Pilot footprint is one representative point per entity. Keeping every
    # way vertex would turn a bounded measurement into an unbounded memory and
    # H3 workload; production geometry retention is Phase 4B.
    lat = sum(point[0] for point in points) / len(points)
    lon = sum(point[1] for point in points) / len(points)
    return [(lat, lon)]


def scan_pbf(path: Path, country: str, resolutions: tuple[int, ...] = DEFAULT_RESOLUTIONS) -> PilotMetrics:
    """Stream PBF entities; cheap tag filter precedes geometry extraction."""
    try:
        import osmium
    except ImportError as exc:
        raise RuntimeError("PBF pilot requires osmium; install project requirements") from exc
    metrics = PilotMetrics(country=country, source_path=str(path), pbf_bytes=path.stat().st_size)
    cells_by_resolution = {resolution: set() for resolution in resolutions}
    filter_started = time.perf_counter()

    class Handler(osmium.SimpleHandler):
        def _visit(self, entity: Any) -> None:
            metrics.entities_seen += 1
            tags = _entity_tags(entity)
            if not tags:
                return
            metrics.candidates_seen += 1
            sectors = classify_tags(tags)
            if not sectors:
                metrics.rejected_by_tag += 1
                return
            metrics.retained_observations += len(sectors)
            geometry_started = time.perf_counter()
            points = _entity_points(entity)
            metrics.geometry_seconds += time.perf_counter() - geometry_started
            for sector in sectors:
                for lat, lon in points:
                    for resolution in resolutions:
                        h3_started = time.perf_counter()
                        cell_id = _cell(lat, lon, resolution)
                        cells_by_resolution[resolution].add(cell_id)
                        key = f"res{resolution}"
                        metrics.h3_seconds[key] = metrics.h3_seconds.get(key, 0.0) + time.perf_counter() - h3_started
                        if resolution == production_resolution():
                            feature_key = f"{resolution}|{cell_id}|{sector.lower()}"
                            counts = _feature_counts(tags, sector)
                            feature = metrics.cell_features.setdefault(feature_key, {name: 0 for name in counts})
                            for name, value in counts.items():
                                feature[name] += value

        def node(self, entity: Any) -> None:
            self._visit(entity)

        def way(self, entity: Any) -> None:
            metrics.way_entities += 1
            self._visit(entity)
            if _entity_points(entity):
                metrics.ways_with_geometry += 1
            else:
                metrics.ways_missing_geometry += 1

    Handler().apply_file(str(path), locations=True, idx="flex_mem")
    metrics.filter_seconds = time.perf_counter() - filter_started - metrics.geometry_seconds - sum(metrics.h3_seconds.values())
    metrics.scan_seconds = metrics.filter_seconds
    metrics.h3_cells = {f"res{resolution}": len(cells) for resolution, cells in cells_by_resolution.items()}
    metrics.source_sha256 = sha256_file(path)
    metrics.peak_rss_bytes = _rss_bytes()
    return metrics


def run_native_pipeline(path: Path, country: str, cache_dir: Path, resolutions: tuple[int, ...] = DEFAULT_RESOLUTIONS,
                        budget_seconds: float = 600.0) -> dict[str, Any]:
    candidate = cache_dir / f"{country.lower()}-{FILTER_VERSION}.osm.pbf"
    native = native_prefilter(path, candidate, budget_seconds)
    metrics = scan_pbf(candidate, country, resolutions)
    report = metrics.as_dict()
    report.update({"original_pbf_bytes": native["original_bytes"], "candidate_pbf_bytes": native["candidate_bytes"],
                   "native_filter_seconds": native["seconds"], "candidate_reduction_ratio": native["reduction_ratio"],
                   "filter_version": FILTER_VERSION, "source_hash": sha256_file(path),
                   "candidate_path": str(candidate)})
    return report


def persist_report(repo: Any, report: dict[str, Any], source_url: str, source_version: str) -> dict[str, Any]:
    """Persist one fully-built staging snapshot, then activate atomically."""
    resolution = production_resolution()
    country = report["country"]
    snapshot_id = f"osm:{country}:{report['source_hash'][:16]}:{CLASSIFICATION_VERSION}:r{resolution}"
    repo.upsert_osm_snapshot({
        "snapshot_id": snapshot_id, "country_code": country, "source_url": source_url,
        "source_version": source_version, "source_hash": report["source_hash"],
        "filter_version": FILTER_VERSION, "classification_version": CLASSIFICATION_VERSION,
        "h3_resolution": resolution, "status": "staging",
    })
    features, opportunity = [], []
    for key, counts in report.get("cell_features", {}).items():
        raw_resolution, cell_id, track = key.split("|", 2)
        raw = {"snapshot_id": snapshot_id, "country_code": country, "h3_cell_id": cell_id,
               "h3_resolution": int(raw_resolution), "track": track, "source": "osm",
               "source_version": source_version, "classification_version": CLASSIFICATION_VERSION, **counts}
        features.append(raw)
        opportunity.append({"snapshot_id": snapshot_id, "country_code": country, "h3_cell_id": cell_id,
                            "h3_resolution": int(raw_resolution), "track": track,
                            "evidence_count": counts.get("osm_feature_count", 0)})
    feature_count = repo.upsert_cell_features(features)
    opportunity_count = repo.upsert_opportunity_cells(opportunity)
    active = repo.activate_osm_snapshot(country, snapshot_id)
    return {"status": "active", "snapshot_id": snapshot_id, "features": feature_count,
            "opportunity_cells": opportunity_count, "active": active}


def refresh_osm_pilot(repo: Any, countries: Iterable[str] | None = None) -> dict[str, Any]:
    """Scheduler-owned bounded pilot refresh; never called by FastAPI."""
    from app.config.settings import DATA_DIR

    selected = [str(code).strip().upper() for code in (countries or os.getenv("OSM_COUNTRIES", ",".join(PRIORITY_COUNTRIES)).split(",")) if str(code).strip()]
    unknown = sorted(set(selected) - set(SUPPORTED_OSM_COUNTRIES))
    if unknown:
        raise ValueError(f"OSM source is not registered for country: {unknown}")
    cache_dir = Path(os.getenv("OSM_CACHE_DIR", str(DATA_DIR / "geography" / "osm" / "scale")))
    source_dir = cache_dir / "sources"
    source_dir.mkdir(parents=True, exist_ok=True)
    candidate_dir = cache_dir / "candidates"
    reports = {}
    for country in selected:
        source_url, source_kind = resolve_osm_source(country)
        source_version = os.getenv(f"OSM_SOURCE_VERSION_{country}", "configured")
        source_path = Path(os.getenv(f"OSM_PBF_PATH_{country}", str(source_dir / f"{country.lower()}.osm.pbf")))
        job_key = f"osm:{country}"
        try:
            disk_preflight = preflight_osm_source(country, cache_dir)
            if disk_preflight["status"] == "blocked_disk_hard_limit":
                reports[country] = {"status": "blocked", "reason": disk_preflight["status"],
                                    "source_kind": source_kind, "disk_preflight": disk_preflight}
                continue
            previous_job = repo.get_job_state(job_key)
            repo.upsert_job_state({"job_key": job_key, "source": "osm", "country_code": country,
                                   "status": "downloading", "current_step": "downloading", "source_version": source_version})
            _, downloaded = download_snapshot(source_url, source_path, float(os.getenv("OSM_DOWNLOAD_TIMEOUT", "120")))
            source_hash = sha256_file(source_path)
            active = repo.active_osm_snapshot(country)
            if previous_job and previous_job.get("status") == "done" and previous_job.get("source_hash") == source_hash and active and active.get("source_hash") == source_hash:
                repo.upsert_job_state({"job_key": job_key, "source": "osm", "country_code": country,
                                       "status": "done", "current_step": "done", "source_version": source_version,
                                       "source_hash": source_hash})
                reports[country] = {"status": "skipped_unchanged", "source_hash": source_hash, "downloaded_bytes": downloaded,
                                    "disk_preflight": disk_preflight}
                continue
            repo.upsert_job_state({"job_key": job_key, "source": "osm", "country_code": country,
                                   "status": "prefiltering", "current_step": "prefiltering", "source_version": source_version, "source_hash": source_hash})
            report = run_native_pipeline(source_path, country, candidate_dir, (production_resolution(),), float(os.getenv("OSM_BUDGET_SECONDS", "900")))
            report["downloaded_bytes"] = downloaded
            repo.upsert_job_state({"job_key": job_key, "source": "osm", "country_code": country,
                                   "status": "processing", "current_step": "processing", "source_version": source_version, "source_hash": source_hash})
            persisted = persist_report(repo, report, source_url, source_version)
            repo.upsert_job_state({"job_key": job_key, "source": "osm", "country_code": country,
                                   "status": "validating", "current_step": "validating", "source_version": source_version, "source_hash": source_hash})
            if not repo.active_osm_snapshot(country) or repo.active_osm_snapshot(country)["snapshot_id"] != persisted["snapshot_id"]:
                raise RuntimeError("OSM snapshot activation verification failed")
            candidate_path = Path(report["candidate_path"]) if report.get("candidate_path") else None
            if candidate_path and candidate_path.exists():
                candidate_path.unlink()
            removed_sources = remove_superseded_sources(source_dir, country, source_path)
            repo.upsert_job_state({"job_key": job_key, "source": "osm", "country_code": country,
                                   "status": "done", "current_step": "done", "source_version": source_version, "source_hash": source_hash})
            metrics = {key: value for key, value in report.items() if key != "cell_features"}
            metrics["raw_feature_rows"] = len(report.get("cell_features", {}))
            reports[country] = {"status": "updated", "source_hash": source_hash, "persisted": persisted,
                                "removed_superseded_sources": removed_sources, "metrics": metrics,
                                "disk_preflight": disk_preflight}
        except Exception as exc:
            repo.upsert_job_state({"job_key": job_key, "source": "osm", "country_code": country,
                                   "status": "failed", "current_step": "failed", "source_version": source_version,
                                   "last_error": f"{type(exc).__name__}: {exc}"[:240]})
            reports[country] = {"status": "failed", "error": type(exc).__name__, "message": str(exc)[:240]}
    failed = [country for country, result in reports.items() if result["status"] in {"failed", "blocked"}]
    return {"status": "partial" if failed else "completed", "countries": reports, "failed": failed}


def safe_snapshot_activation(active: dict[str, str], incoming: dict[str, str], failed: bool = False) -> dict[str, str]:
    """N/N+1 manifest swap; failed preparation leaves N active."""
    return dict(active if failed else incoming)


def run_pilot(paths: dict[str, Path], resolutions: tuple[int, ...] = DEFAULT_RESOLUTIONS) -> dict[str, Any]:
    started = time.perf_counter()
    reports = [scan_pbf(path, country, resolutions) for country, path in paths.items()]
    return {"phase": "4A", "status": "completed", "countries": [item.country for item in reports], "wall_seconds": time.perf_counter() - started, "reports": [item.as_dict() for item in reports], "scope": {"sectors": sorted(SECTOR_TAGS), "resolutions": list(resolutions), "scores": False}}


def main() -> None:
    parser = argparse.ArgumentParser(description="Run offline OSM/H3 Phase 4A pilot")
    parser.add_argument("--country", action="append", choices=PILOTS, dest="countries")
    parser.add_argument("--pbf", action="append", nargs=2, metavar=("ISO2", "PATH"))
    parser.add_argument("--scale-benchmark", action="store_true")
    parser.add_argument("--source-preflight", action="store_true",
                        help="Resolve registered sources and run HEAD/disk checks only")
    parser.add_argument("--preflight-country", action="append", dest="preflight_countries",
                        help="Country code for --source-preflight; defaults to W1")
    retention_group = parser.add_mutually_exclusive_group()
    retention_group.add_argument("--retention-dry-run", action="store_true",
                                 help="Plan safe cache eviction from read-only DB metadata")
    retention_group.add_argument("--retention-apply", action="store_true",
                                 help="Apply a validated safe cache eviction plan")
    parser.add_argument("--retention-target-gib", type=float, default=3.0)
    parser.add_argument("--scale-country", action="append", choices=SCALE_COUNTRIES)
    parser.add_argument("--disk-budget-gib", type=float, default=10.0)
    parser.add_argument("--retain-sources", action="store_true")
    parser.add_argument("--resolution", action="append", type=int, dest="resolutions")
    parser.add_argument("--native-prefilter", action="store_true")
    parser.add_argument("--cache-dir", type=Path, default=None)
    parser.add_argument("--budget-seconds", type=float, default=600.0)
    parser.add_argument("--persist", action="store_true")
    parser.add_argument("--source-url", default="local://operator-provided-pbf")
    parser.add_argument("--source-version", default="operator-provided")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.retention_dry_run or args.retention_apply:
        cache_dir = args.cache_dir or Path(os.getenv("OSM_CACHE_DIR", "data/geography/osm/scale"))
        from app.db.market_repository import MarketRepository
        from app.db.postgres import close_pool
        repository = MarketRepository()
        try:
            active, busy = [], []
            for country in SUPPORTED_OSM_COUNTRIES:
                snapshot = repository.active_osm_snapshot(country)
                job = repository.get_job_state(f"osm:{country}")
                if snapshot and snapshot.get("active"):
                    active.append(country)
                if job and job.get("status") in RETENTION_BUSY_STATUSES:
                    busy.append(country)
            plan = cache_retention_plan(cache_dir, active, busy, int(args.retention_target_gib * 1024 ** 3))
            report = {"plan": plan}
            if args.retention_apply:
                report["apply"] = apply_cache_retention(plan)
        finally:
            close_pool()
        encoded = json.dumps(report, indent=2, sort_keys=True)
        if args.output:
            args.output.write_text(encoded + "\n", encoding="utf-8")
        print(encoded)
        return
    if args.source_preflight:
        cache_dir = args.cache_dir or Path(os.getenv("OSM_CACHE_DIR", "data/geography/osm/scale"))
        report = preflight_osm_sources(args.preflight_countries or WAVE_1_COUNTRIES, cache_dir)
        encoded = json.dumps(report, indent=2, sort_keys=True)
        if args.output:
            args.output.write_text(encoded + "\n", encoding="utf-8")
        print(encoded)
        return
    if args.scale_benchmark:
        scale_cache_dir = args.cache_dir or Path("data/geography/osm/scale")
        report = run_scale_benchmark(args.scale_country or SCALE_COUNTRIES, scale_cache_dir,
                                     int(args.disk_budget_gib * 1024 ** 3), args.budget_seconds, args.retain_sources)
        encoded = json.dumps(report, indent=2, sort_keys=True)
        if args.output:
            args.output.write_text(encoded + "\n", encoding="utf-8")
        print(encoded)
        return
    if not args.pbf:
        raise SystemExit("--pbf is required unless --scale-benchmark is set")
    countries = set(args.countries or PILOTS)
    paths = {country.upper(): Path(path) for country, path in args.pbf if country.upper() in countries}
    if set(paths) != countries:
        raise SystemExit(f"PBF path required for each selected pilot country: {sorted(countries - set(paths))}")
    resolutions = tuple(args.resolutions or DEFAULT_RESOLUTIONS)
    if args.native_prefilter:
        pilot_cache_dir = args.cache_dir or Path("data/geography/osm/candidates")
        reports = [run_native_pipeline(path, country, pilot_cache_dir, resolutions, args.budget_seconds)
                   for country, path in paths.items()]
        report = {"phase": "4A.1", "status": "completed", "countries": list(paths), "reports": reports,
                  "scope": {"filter_version": FILTER_VERSION, "sectors": sorted(SECTOR_TAGS), "resolutions": list(resolutions), "scores": False}}
        if args.persist:
            from app.db.market_repository import MarketRepository
            report["persistence"] = [persist_report(MarketRepository(), item, args.source_url, args.source_version)
                                      for item in reports]
    else:
        report = run_pilot(paths, resolutions)
    encoded = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(encoded + "\n", encoding="utf-8")
    print(encoded)


if __name__ == "__main__":
    main()
