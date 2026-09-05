"""LC-2B.2: weighted city summary and city-level percentile calibration."""
from __future__ import annotations
import json
import os
from collections import defaultdict
from typing import Any, Iterable
from app.db.market_repository import MarketRepository

CITY_SUMMARY_MODEL_VERSION = "lc2b-city-summary-v1"
CITY_CALIBRATION_VERSION = "lc2b-city-cal-v1"

def build_city_summaries(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        key = (row["snapshot_id"],row["country_code"],row["city_id"],row["track"],row.get("model_version") or "unknown")
        groups[key].append(row)
    result = []
    for key in sorted(groups, key=lambda value: tuple(str(part) for part in value)):
        snapshot,country,city,track,model = key
        members = groups[key]
        weights = [float(row["membership_fraction"]) for row in members]
        scored = [row for row in members if row.get("evidence_status") == "scored" and row.get("raw_local_score") is not None]
        scored_weight = sum(float(row["membership_fraction"]) for row in scored)
        total_weight = sum(weights)
        result.append({"snapshot_id": snapshot,"country_code": country,"city_id": city,"track": track,
            "total_cells": len(members),"scored_cells": len(scored),"membership_weight": total_weight,
            "scored_membership_weight": scored_weight,"evidence_coverage": scored_weight / total_weight if total_weight else 0,
            "city_raw_score": sum(float(row["raw_local_score"]) * float(row["membership_fraction"]) for row in scored) / scored_weight if scored_weight else None,
            "city_calibrated_score": None,"city_percentile": None,
            "evidence_status": "scored" if scored_weight else "insufficient_local_evidence",
            "missing_reason": None if scored_weight else "insufficient_local_evidence",
            "geometry_source": members[0]["geometry_source"],"model_version": model,"calibration_version": None})
    return result

def calibrate_city_summaries(summaries: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    summaries = list(summaries)
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in summaries:
        if row.get("city_raw_score") is not None:
            groups[row["track"]].append(row)
    result = []
    for track in sorted(groups):
        group = groups[track]
        values = sorted(float(row["city_raw_score"]) for row in group)
        for row in group:
            value = float(row["city_raw_score"])
            percentile = (sum(current <= value for current in values) - .5) / len(values)
            result.append({**row,"city_calibrated_score": round(percentile * 100, 6),
                           "city_percentile": round(percentile, 6),"calibration_version": CITY_CALIBRATION_VERSION})
    calibrated_by_key = {(row["snapshot_id"],row["country_code"],row["city_id"],row["track"]): row for row in result}
    return [calibrated_by_key.get((row["snapshot_id"],row["country_code"],row["city_id"],row["track"]), row) for row in summaries]

def refresh_city_summaries(repo: MarketRepository, countries: Iterable[str] | None = None) -> dict[str, Any]:
    rows = repo.list_city_summary_inputs(countries)
    summaries = build_city_summaries(rows)
    calibrated = calibrate_city_summaries(summaries)
    persisted = repo.upsert_city_opportunity_summaries(calibrated or summaries)
    return {"status":"completed","input_memberships":len(rows),"city_summaries":len(summaries),
            "calibrated":len(calibrated),"persisted":persisted,"summary_version":CITY_SUMMARY_MODEL_VERSION,
            "calibration_version":CITY_CALIBRATION_VERSION}

if __name__ == "__main__":
    from ..db import postgres
    try:
        print(json.dumps(refresh_city_summaries(MarketRepository()), indent=2))
    finally:
        postgres.close_pool()
