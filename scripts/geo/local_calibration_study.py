"""Read-only Phase 6B.3 distribution and calibration study."""

from __future__ import annotations

import math
import json
import statistics
from collections import defaultdict
from typing import Any, Iterable

STUDY_VERSION = "phase6b-study-v2"


def _percentile(values: list[float], ratio: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * ratio
    lower, upper = math.floor(position), math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def summarize(values: Iterable[float]) -> dict[str, Any]:
    ordered = sorted(float(value) for value in values)
    if not ordered:
        return {"count": 0, "median": None, "iqr": None, "p5": None, "p25": None,
                "p75": None, "p95": None, "skew": None, "lower_fence": None,
                "upper_fence": None, "outlier_count_low": 0, "outlier_count_high": 0,
                "outlier_percentage": 0.0}
    p25, p75 = _percentile(ordered, .25), _percentile(ordered, .75)
    median = statistics.median(ordered)
    iqr = p75 - p25
    mean = statistics.fmean(ordered)
    deviation = statistics.pstdev(ordered)
    skew = (statistics.fmean((value - mean) ** 3 for value in ordered) / deviation ** 3) if deviation else 0.0
    lower_fence = p25 - 1.5 * iqr
    upper_fence = p75 + 1.5 * iqr
    outlier_count_low = sum(value < lower_fence for value in ordered)
    outlier_count_high = sum(value > upper_fence for value in ordered)
    return {"count": len(ordered), "median": median, "iqr": iqr, "p5": _percentile(ordered, .05),
            "p25": p25, "p75": p75, "p95": _percentile(ordered, .95), "skew": skew,
            "range": {"min": ordered[0], "max": ordered[-1]},
            "lower_fence": lower_fence, "upper_fence": upper_fence,
            "outlier_count_low": outlier_count_low, "outlier_count_high": outlier_count_high,
            "outlier_percentage": (outlier_count_low + outlier_count_high) * 100 / len(ordered)}


def candidate_calibrations(values: Iterable[float]) -> dict[str, list[float]]:
    ordered = sorted(float(value) for value in values)
    if not ordered:
        return {"percentile": [], "robust_quantile": [], "robust_z": []}
    median = statistics.median(ordered)
    p25, p75 = _percentile(ordered, .25), _percentile(ordered, .75)
    iqr = p75 - p25
    percentile = [(sum(value <= current for value in ordered) - .5) / len(ordered) for current in ordered]
    robust_quantile = [min(1.0, max(0.0, (value - p25) / iqr)) if iqr else .5 for value in ordered]
    robust_z = [min(1.0, max(0.0, .5 + .25 * (value - median) / iqr)) if iqr else .5 for value in ordered]
    return {"percentile": percentile, "robust_quantile": robust_quantile, "robust_z": robust_z}


def run_study(repo: Any, countries: Iterable[str] | None = None) -> dict[str, Any]:
    selected = {str(code).upper() for code in countries} if countries else None
    groups: dict[tuple[str, str], list[float]] = defaultdict(list)
    for row in repo.list_raw_local_scores():
        if selected and row["country_code"] not in selected:
            continue
        groups[(row["track"], row.get("area_type") or "unmapped")].append(float(row["raw_local_score"]))
    distributions = {}
    candidates = {}
    for key, values in sorted(groups.items()):
        label = f"{key[0]}:{key[1]}"
        distributions[label] = summarize(values)
        candidates[label] = {name: summarize(result) for name, result in candidate_calibrations(values).items()}
    return {"study_version": STUDY_VERSION, "groups": distributions, "candidate_distributions": candidates,
            "total_scored": sum(item["count"] for item in distributions.values())}


def main() -> int:
    from ..db import postgres
    from ..db.market_repository import MarketRepository
    try:
        print(json.dumps(run_study(MarketRepository()), indent=2))
        return 0
    finally:
        postgres.close_pool()


if __name__ == "__main__":
    raise SystemExit(main())
