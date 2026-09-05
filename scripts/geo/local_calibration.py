"""Phase 6B.4-B: select and persist track-specific local calibration."""

from __future__ import annotations

import math
import random
import statistics
from collections import defaultdict
from typing import Any

CALIBRATION_VERSION = "phase6b-cal-v1"
METHODS = ("percentile", "robust_z")
SEED = 60425
ITERATIONS = 20
SAMPLE_FRACTION = 0.8


def _percentile(values: list[float], ratio: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * ratio
    lower, upper = math.floor(position), math.ceil(position)
    return ordered[lower] if lower == upper else ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def _transform(values: list[float], method: str, fit_values: list[float] | None = None) -> list[float]:
    fit = sorted(fit_values or values)
    if method == "percentile":
        return [(sum(value <= current for value in fit) - 0.5) / len(fit) for current in values]
    median = statistics.median(fit)
    iqr = _percentile(fit, .75) - _percentile(fit, .25)
    return [min(1.0, max(0.0, .5 + .25 * (value - median) / iqr)) if iqr else .5 for value in values]


def _rank(values: list[float]) -> list[float]:
    ordered = sorted(enumerate(values), key=lambda pair: pair[1])
    ranks = [0.0] * len(values)
    index = 0
    while index < len(ordered):
        end = index + 1
        while end < len(ordered) and ordered[end][1] == ordered[index][1]:
            end += 1
        rank = (index + end - 1) / 2 + 1
        for position in range(index, end):
            ranks[ordered[position][0]] = rank
        index = end
    return ranks


def _correlation(left: list[float], right: list[float]) -> float:
    if len(left) < 2:
        return 1.0
    left_mean, right_mean = statistics.fmean(left), statistics.fmean(right)
    numerator = sum((a - left_mean) * (b - right_mean) for a, b in zip(left, right))
    denominator = math.sqrt(sum((a - left_mean) ** 2 for a in left) * sum((b - right_mean) ** 2 for b in right))
    return numerator / denominator if denominator else 1.0


def _stability(values: list[float], method: str) -> dict[str, float]:
    full = _transform(values, method)
    rng = random.Random(SEED)
    correlations, median_shifts, p95_shifts = [], [], []
    top_retention, bottom_retention = [], []
    sample_size = max(10, int(len(values) * SAMPLE_FRACTION))
    for _ in range(ITERATIONS):
        retained = sorted(rng.sample(range(len(values)), sample_size))
        fitted = _transform([values[i] for i in retained], method)
        full_retained = [full[i] for i in retained]
        correlations.append(_correlation(_rank(full_retained), _rank(fitted)))
        shifts = sorted(abs(a - b) for a, b in zip(full_retained, fitted))
        median_shifts.append(statistics.median(shifts))
        p95_shifts.append(_percentile(shifts, .95))
        top_cut = _percentile(full_retained, .9)
        bottom_cut = _percentile(full_retained, .1)
        top = {i for i, value in enumerate(fitted) if value >= _percentile(fitted, .9)}
        bottom = {i for i, value in enumerate(fitted) if value <= _percentile(fitted, .1)}
        full_top = {i for i, value in enumerate(full_retained) if value >= top_cut}
        full_bottom = {i for i, value in enumerate(full_retained) if value <= bottom_cut}
        top_retention.append(len(top & full_top) / len(full_top) if full_top else 1.0)
        bottom_retention.append(len(bottom & full_bottom) / len(full_bottom) if full_bottom else 1.0)
    return {"spearman_rank_correlation": statistics.fmean(correlations),
            "median_absolute_score_shift": statistics.median(median_shifts),
            "p95_score_shift": _percentile(p95_shifts, .95),
            "top_decile_retention": statistics.fmean(top_retention),
            "bottom_decile_retention": statistics.fmean(bottom_retention)}


def _select(metrics: dict[str, dict[str, float]]) -> str | None:
    if not metrics:
        return None
    # Deterministic ordering: stability first, then tail distortion, then shift.
    return min(METHODS, key=lambda method: (-metrics[method]["spearman_rank_correlation"],
                                             metrics[method]["p95_score_shift"],
                                             metrics[method]["median_absolute_score_shift"],
                                             METHODS.index(method)))


def run_calibration(repo: Any) -> dict[str, Any]:
    rows = repo.list_calibration_candidates()
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[row["track"]].append(row)
    report: dict[str, Any] = {"calibration_version": CALIBRATION_VERSION, "groups": {}, "updated": 0}
    updates = []
    for track, group in sorted(groups.items()):
        values = [float(row["raw_local_score"]) for row in group]
        metrics = {method: _stability(values, method) for method in METHODS} if len(values) >= 20 else {}
        selected = _select(metrics)
        peer = _transform(values, "percentile") if selected else [None] * len(group)
        calibrated = _transform(values, selected) if selected else [None] * len(group)
        report["groups"][track] = {"count": len(group), "selected_method": selected, "metrics": metrics,
                                   "status": "selected" if selected else "insufficient_stability"}
        for row, calibrated_score, percentile in zip(group, calibrated, peer):
            updates.append({**row, "calibrated_score": round(calibrated_score, 6) if calibrated_score is not None else None,
                            "peer_percentile": round(percentile, 6) if percentile is not None else None,
                            "calibration_method": selected, "calibration_version": CALIBRATION_VERSION,
                            "calibration_status": "selected" if selected else "insufficient_stability"})
    report["updated"] = repo.update_local_calibration(updates)
    return report


def main() -> int:
    import json
    from ..db import postgres
    from ..db.market_repository import MarketRepository
    try:
        print(json.dumps(run_calibration(MarketRepository()), indent=2))
        return 0
    finally:
        postgres.close_pool()


if __name__ == "__main__":
    raise SystemExit(main())
