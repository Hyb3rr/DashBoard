"""Scheduler-owned LC-1B area opportunity summary refresh."""

from __future__ import annotations

import os
from collections import defaultdict
from typing import Any, Iterable

from app.db.market_repository import MarketRepository
from scripts.geo.osm_h3_pilot import PRIORITY_COUNTRIES

AREA_SUMMARY_VERSION = "phase6b-area-summary-v1"


def build_area_summaries(rows: Iterable[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Aggregate raw cell scores by active snapshot, area and track.

    The mean is calculated only over scored cells.  Coverage remains a
    separate signal and does not reduce the raw score.
    """
    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    unmapped = 0
    for row in rows:
        if not row.get("area_id"):
            unmapped += 1
            continue
        key = (
            row["snapshot_id"], row["country_code"], int(row["h3_resolution"]),
            row["area_id"], row["track"], row["model_version"],
        )
        groups[key].append(row)

    summaries: list[dict[str, Any]] = []
    for key in sorted(groups, key=lambda value: tuple(str(part) for part in value)):
        snapshot_id, country, resolution, area_id, track, model_version = key
        members = groups[key]
        scored = [row for row in members if row.get("raw_local_score") is not None and row.get("evidence_status") == "scored"]
        total_cells = len(members)
        scored_cells = len(scored)
        summary = {
            "snapshot_id": snapshot_id,
            "country_code": country,
            "h3_resolution": resolution,
            "area_id": area_id,
            "track": track,
            "total_cells": total_cells,
            "scored_cells": scored_cells,
            "evidence_coverage": scored_cells / total_cells if total_cells else 0.0,
            "area_raw_score": round(sum(float(row["raw_local_score"]) for row in scored) / scored_cells, 6) if scored_cells else None,
            "area_calibrated_score": None,
            "area_percentile": None,
            "evidence_status": "scored" if scored_cells else "insufficient_local_evidence",
            "missing_reason": None if scored_cells else "insufficient_local_evidence",
            "model_version": model_version,
            "calibration_version": None,
        }
        summaries.append(summary)
    return summaries, {"input_rows": unmapped + sum(len(items) for items in groups.values()), "unmapped_rows": unmapped}


def refresh_area_summaries(repo: MarketRepository, countries: Iterable[str] | None = None) -> dict[str, Any]:
    selected = [str(code).strip().upper() for code in (countries or os.getenv("OSM_COUNTRIES", ",".join(PRIORITY_COUNTRIES)).split(",")) if str(code).strip()]
    reports: dict[str, Any] = {}
    for country in selected:
        try:
            rows = repo.list_active_area_summary_inputs(country)
            summaries, counts = build_area_summaries(rows)
            persisted = repo.upsert_area_opportunity_summaries(summaries)
            reports[country] = {
                "status": "updated",
                "input_rows": counts["input_rows"],
                "unmapped_rows": counts["unmapped_rows"],
                "areas_summarized": len(summaries),
                "track_summaries": sum(1 for _ in summaries),
                "persisted": persisted,
            }
        except Exception as exc:
            reports[country] = {"status": "failed", "error": type(exc).__name__, "message": str(exc)[:240]}
    failed = [country for country, result in reports.items() if result["status"] == "failed"]
    return {"status": "partial" if failed else "completed", "countries": reports, "failed": failed,
            "summary_version": AREA_SUMMARY_VERSION}


if __name__ == "__main__":
    import json
    from ..db import postgres
    try:
        print(json.dumps(refresh_area_summaries(MarketRepository()), indent=2, default=str))
    finally:
        postgres.close_pool()
