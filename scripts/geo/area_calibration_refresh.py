"""LC-1C: percentile calibration of persisted area raw scores."""

from __future__ import annotations

import json
import os
from collections import defaultdict
from typing import Any, Iterable

from app.db.market_repository import MarketRepository

AREA_CALIBRATION_VERSION = "phase6b-area-cal-v1"


def calibrate_area_summaries(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        if row.get("area_raw_score") is not None:
            groups[(row["track"], row.get("area_type") or "unknown")].append(row)
    result = []
    for key in sorted(groups):
        group = groups[key]
        values = sorted(float(row["area_raw_score"]) for row in group)
        for row in group:
            value = float(row["area_raw_score"])
            percentile = (sum(current <= value for current in values) - 0.5) / len(values)
            result.append({**row, "area_calibrated_score": round(percentile * 100, 6),
                           "area_percentile": round(percentile, 6),
                           "calibration_version": AREA_CALIBRATION_VERSION})
    return sorted(result, key=lambda row: (row["country_code"], row["track"], row["area_id"]))


def refresh_area_calibration(repo: MarketRepository, countries: Iterable[str] | None = None) -> dict[str, Any]:
    selected = {str(code).strip().upper() for code in (countries or os.getenv("OSM_COUNTRIES", "").split(",")) if str(code).strip()}
    rows = [row for row in repo.list_area_summaries_for_calibration() if not selected or row["country_code"] in selected]
    updates = calibrate_area_summaries(rows)
    updated = repo.update_area_calibration(updates)
    return {"status": "completed", "calibration_version": AREA_CALIBRATION_VERSION,
            "summaries_seen": len(rows), "summaries_updated": updated,
            "groups": len({(row["track"], row.get("area_type")) for row in rows})}


if __name__ == "__main__":
    from ..db import postgres
    try:
        print(json.dumps(refresh_area_calibration(MarketRepository()), indent=2))
    finally:
        postgres.close_pool()
