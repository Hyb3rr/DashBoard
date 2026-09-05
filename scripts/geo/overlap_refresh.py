"""Phase 7B: compute directional overlap and whitespace from calibrated cells."""

from __future__ import annotations

import json
import os
from collections import defaultdict
from typing import Any, Iterable

from app.db import postgres
from app.db.market_repository import MarketRepository
from scripts.geo.osm_h3_pilot import PRIORITY_COUNTRIES

OVERLAP_VERSION = "phase7b-overlap-v1"


def compute_overlap(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build only pairs sharing a calibrated H3 cell."""
    cells: dict[tuple[str, str, str, int, str], dict[str, float]] = defaultdict(dict)
    for row in rows:
        if row.get("calibrated_score") is None or not row.get("area_id"):
            continue
        key = (row["snapshot_id"], row["country_code"], row["track"], int(row["h3_resolution"]), row["h3_cell_id"])
        cells[key][row["area_id"]] = float(row["calibrated_score"])
    opportunities: dict[tuple[str, str, str, int], dict[str, float]] = defaultdict(lambda: defaultdict(float))
    shared: dict[tuple[str, str, str, int, str, str], float] = defaultdict(float)
    for (snapshot, country, track, resolution, _cell), memberships in cells.items():
        areas = sorted(memberships)
        for area in areas:
            opportunities[(snapshot, country, track, resolution)][area] += memberships[area]
        for index, area_a in enumerate(areas):
            for area_b in areas[index + 1:]:
                shared[(snapshot, country, track, resolution, area_a, area_b)] += min(memberships[area_a], memberships[area_b])
    result = []
    for (snapshot, country, track, resolution, area_a, area_b), shared_value in sorted(shared.items()):
        totals = opportunities[(snapshot, country, track, resolution)]
        opportunity_a, opportunity_b = totals[area_a], totals[area_b]
        result.append({"snapshot_id": snapshot, "country_code": country, "track": track,
                       "h3_resolution": resolution, "area_id_a": area_a, "area_id_b": area_b,
                       "shared_opportunity": shared_value, "opportunity_a": opportunity_a,
                       "opportunity_b": opportunity_b,
                       "overlap_a_to_b": shared_value / opportunity_a if opportunity_a else 0,
                       "overlap_b_to_a": shared_value / opportunity_b if opportunity_b else 0,
                       "remaining_opportunity_a": max(0.0, opportunity_a - shared_value),
                       "remaining_opportunity_b": max(0.0, opportunity_b - shared_value),
                       "calculation_version": OVERLAP_VERSION})
    return result


def refresh_overlap(repo: MarketRepository, countries: Iterable[str] | None = None) -> dict[str, Any]:
    selected = [str(code).strip().upper() for code in (countries or os.getenv("OSM_COUNTRIES", ",".join(PRIORITY_COUNTRIES)).split(",")) if str(code).strip()]
    reports = {}
    for country in selected:
        job_key = f"overlap:{country}"
        try:
            rows = repo.list_calibrated_cells_for_overlap(country)
            items = compute_overlap(rows)
            scopes = sorted({(item["snapshot_id"], item["track"], item["h3_resolution"]) for item in items})
            for snapshot_id, track, resolution in scopes:
                scoped = [item for item in items if item["snapshot_id"] == snapshot_id and item["track"] == track and item["h3_resolution"] == resolution]
                repo.replace_area_overlap(country, snapshot_id, track, resolution, scoped)
            repo.upsert_job_state({"job_key": job_key, "source": "overlap", "country_code": country,
                                   "status": "done", "current_step": "done", "source_version": OVERLAP_VERSION})
            reports[country] = {"status": "updated", "cells_seen": len(rows), "pairs": len(items)}
        except Exception as exc:
            reports[country] = {"status": "failed", "error": type(exc).__name__, "message": str(exc)[:240]}
    failed = [country for country, result in reports.items() if result["status"] == "failed"]
    return {"status": "partial" if failed else "completed", "countries": reports, "failed": failed}


def main() -> int:
    try:
        print(json.dumps(refresh_overlap(MarketRepository()), indent=2, default=str))
        return 0
    finally:
        postgres.close_pool()


if __name__ == "__main__":
    raise SystemExit(main())
