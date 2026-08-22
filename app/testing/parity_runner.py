"""Reusable semantic comparison primitives for migration tests.

The runner deliberately does not know about either database. Callers provide
the old/new snapshots, then this module reports only product semantics.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Iterable

from app.db.parity import normalize_detections, semantic_diff_by_ip


@dataclass(frozen=True)
class ParityReport:
    features: dict[str, dict[str, tuple[Any, Any]]]
    states: dict[str, dict[str, tuple[Any, Any]]]
    traffic: dict[str, tuple[Any, Any]]

    @property
    def passed(self) -> bool:
        return not (self.features or self.states or self.traffic)

    def as_dict(self) -> dict[str, Any]:
        return {
            "features": self.features,
            "states": self.states,
            "traffic": self.traffic,
            "passed": self.passed,
        }


def compare(
    old_features: dict[str, dict[str, Any]],
    new_features: dict[str, dict[str, Any]],
    old_states: dict[str, dict[str, Any]],
    new_states: dict[str, dict[str, Any]],
    old_traffic: dict[str, Any] | None = None,
    new_traffic: dict[str, Any] | None = None,
    *,
    traffic_fields: Iterable[str] = (),
) -> ParityReport:
    traffic_diff: dict[str, tuple[Any, Any]] = {}
    old_traffic = old_traffic or {}
    new_traffic = new_traffic or {}
    for field in traffic_fields:
        left, right = old_traffic.get(field), new_traffic.get(field)
        if field in {"top_ips", "top_paths", "top_countries"}:
            left = sorted(left or [], key=str)
            right = sorted(right or [], key=str)
        if left != right:
            traffic_diff[field] = (left, right)
    return ParityReport(
        features=semantic_diff_by_ip(old_features, new_features),
        states=semantic_diff_by_ip(old_states, new_states),
        traffic=traffic_diff,
    )


def format_report(report: ParityReport) -> str:
    lines = ["M2B.6 DETERMINISTIC PARITY", f"status: {'PASS' if report.passed else 'FAIL'}"]
    for section, values in (("features", report.features), ("states", report.states), ("traffic", report.traffic)):
        lines.append(f"{section}: {'PASS' if not values else 'FAIL'}")
        for key, value in values.items():
            lines.append(f"  {key}: {value}")
    return "\n".join(lines)
