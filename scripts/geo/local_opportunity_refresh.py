"""Scheduler-owned Phase 6A.2 raw local opportunity refresh."""

from __future__ import annotations

import math
import os
import time
from typing import Any, Iterable

from app.db.market_repository import MarketRepository
from scripts.geo.osm_h3_pilot import PRIORITY_COUNTRIES

RAW_MODEL_VERSION = "phase6a-raw-v1"


def _bounded_signal(value: int | float, scale: float) -> float:
    return min(1.0, max(0.0, math.log1p(max(0.0, float(value))) / math.log1p(scale)))


def build_local_rows(country: str, demand: float | None, inputs: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for item in inputs:
        osm_count = int(item.get("osm_feature_count") or 0)
        industrial_count = int(item.get("industrial_land_count") or 0)
        access_count = int(item.get("access_observation_count") or 0)
        sector_signal = _bounded_signal(osm_count, 10)
        industrial_signal = _bounded_signal(industrial_count, 5)
        access_signal = _bounded_signal(access_count, 5)
        enough = demand is not None and osm_count > 0 and (industrial_count + access_count) > 0
        components = {
            "country_product_demand": demand,
            "osm_feature_count": osm_count,
            "industrial_land_count": industrial_count,
            "access_observation_count": access_count,
            "sector_signal": round(sector_signal, 6),
            "industrial_signal": round(industrial_signal, 6),
            "access_signal": round(access_signal, 6),
            "formula": "product_demand * mean(sector_signal, industrial_signal, access_signal)",
        }
        rows.append({
            "snapshot_id": item["snapshot_id"], "country_code": country, "area_id": item.get("area_id"),
            "h3_cell_id": item["h3_cell_id"], "h3_resolution": item["h3_resolution"], "track": item["track"],
            "raw_local_score": round(float(demand) * (sector_signal + industrial_signal + access_signal) / 3, 6) if enough else None,
            "evidence_status": "scored" if enough else "insufficient_local_evidence",
            "evidence_components": components,
            "coverage_fields": {"osm_present": osm_count > 0, "auxiliary_present": (industrial_count + access_count) > 0,
                                 "demand_present": demand is not None},
            "model_version": RAW_MODEL_VERSION,
            "missing_reason": None if enough else "insufficient_local_evidence",
        })
    return rows


def refresh_local_opportunity(repo: MarketRepository, countries: Iterable[str] | None = None) -> dict[str, Any]:
    selected = [str(code).strip().upper() for code in (countries or os.getenv("OSM_COUNTRIES", ",".join(PRIORITY_COUNTRIES)).split(",")) if str(code).strip()]
    reports: dict[str, Any] = {}
    for country in selected:
        started = time.perf_counter()
        job_key = f"market_local:{country}"
        try:
            snapshot = repo.active_osm_snapshot(country)
            if not snapshot:
                raise RuntimeError("active OSM snapshot is required")
            demand = repo.country_product_demand(country)
            inputs = repo.list_active_local_inputs(country)
            source_hash = snapshot["source_hash"]
            previous = repo.get_job_state(job_key)
            if previous and previous.get("status") == "done" and previous.get("source_hash") == source_hash:
                reports[country] = {"status": "skipped_unchanged", "source_hash": source_hash}
                continue
            repo.upsert_job_state({"job_key": job_key, "source": "market_local", "country_code": country,
                                   "status": "processing", "current_step": "building_raw_opportunity",
                                   "source_version": RAW_MODEL_VERSION, "source_hash": source_hash})
            rows = build_local_rows(country, demand, inputs)
            persisted = repo.upsert_local_opportunity(rows)
            repo.upsert_job_state({"job_key": job_key, "source": "market_local", "country_code": country,
                                   "status": "done", "current_step": "done", "source_version": RAW_MODEL_VERSION,
                                   "source_hash": source_hash})
            reports[country] = {"status": "updated", "rows": persisted,
                                "scored": sum(row["evidence_status"] == "scored" for row in rows),
                                "insufficient": sum(row["evidence_status"] != "scored" for row in rows),
                                "elapsed_seconds": time.perf_counter() - started}
        except Exception as exc:
            repo.upsert_job_state({"job_key": job_key, "source": "market_local", "country_code": country,
                                   "status": "failed", "current_step": "failed", "source_version": RAW_MODEL_VERSION,
                                   "last_error": f"{type(exc).__name__}: {exc}"[:240]})
            reports[country] = {"status": "failed", "error": type(exc).__name__, "message": str(exc)[:240]}
    failed = [country for country, item in reports.items() if item["status"] == "failed"]
    return {"status": "partial" if failed else "completed", "countries": reports, "failed": failed}
