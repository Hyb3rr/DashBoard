"""Observational calibration report for the frozen V1 country opportunity policy."""

from __future__ import annotations

import json
from statistics import mean, median
from typing import Any

from app.core.country_demand import build_country_opportunities
from app.db.market_repository import MarketRepository
from app.db.repositories import RegionRepository


PERIODS = ("7d", "30d", "90d")
METRICS = ("market_score", "country_demand_score", "demand_confidence", "opportunity_score")


def _distribution(rows: list[dict[str, Any]], metric: str) -> dict[str, Any]:
    """Summarize the observed distribution for one opportunity metric."""
    values = sorted(float(row[metric]) for row in rows if isinstance(row.get(metric), (int, float)))
    return {"count": len(values), "min": round(values[0], 2) if values else None, "median": round(median(values), 2) if values else None, "mean": round(mean(values), 2) if values else None, "max": round(values[-1], 2) if values else None}


def build_calibration_report(snapshots: dict[str, dict[str, Any] | None], market_scores: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Build observational flags and distributions without changing policy."""
    report: dict[str, Any] = {"policy": {"market_weight": 0.60, "demand_weight": 0.40, "neutral_demand": 50.0}, "periods": {}, "flags": []}
    for period in PERIODS:
        result = build_country_opportunities(snapshots, market_scores, period=period)
        rows = result["countries"]
        status_counts: dict[str, int] = {}
        for row in rows:
            status = str(row.get("opportunity_status") or "UNKNOWN")
            status_counts[status] = status_counts.get(status, 0) + 1
            if row.get("opportunity_score") is not None and float(row.get("demand_confidence") or 0) < 0.20:
                report["flags"].append({"period": period, "country_code": row.get("country_code"), "type": "high_score_low_confidence", "opportunity_score": row.get("opportunity_score"), "demand_confidence": row.get("demand_confidence")})
            if row.get("opportunity_status") == "PRIORITIZE" and float(row.get("demand_confidence") or 0) < 0.60:
                report["flags"].append({"period": period, "country_code": row.get("country_code"), "type": "prioritize_below_confidence_threshold"})
        report["periods"][period] = {"country_count": len(rows), "status_counts": status_counts, "distributions": {metric: _distribution(rows, metric) for metric in METRICS}}
    return report


def collect_live_report() -> dict[str, Any]:
    """Load persisted country inputs and return their calibration report."""
    market = MarketRepository()
    snapshots = {period: market.list_latest_country_demand_signals(period) for period in PERIODS}
    regions = RegionRepository().list(limit=250)
    scores = {str(item.get("country_code") or "").upper(): item for item in regions if item.get("country_code")}
    return build_calibration_report(snapshots, scores)


if __name__ == "__main__":
    print(json.dumps(collect_live_report(), indent=2, sort_keys=True))
