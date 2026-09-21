"""Evidence-first overall opportunity score for a province/city read model."""
from __future__ import annotations

from typing import Any, Mapping, Sequence


GROUP_WEIGHTS = {
    "enterprise_base": 0.25,
    "iip": 0.15,
    "fdi_flow": 0.15,
    "fdi_stock": 0.15,
    "local_presence": 0.075,
    "local_park_count": 0.075,
}


def _number(value: Any) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if number == number else None


def _percentile(value: float | None, peers: Sequence[float | None], *, minimum_peers: int = 2) -> float | None:
    if value is None:
        return None
    present = [item for item in peers if item is not None]
    if not present:
        return None
    if len(present) < minimum_peers:
        return None
    if len(present) == 1:
        return 50.0
    less = sum(item < value for item in present)
    equal = sum(item == value for item in present)
    return round((less + equal / 2) / len(present) * 100, 4)


def _enterprise_total(row: Mapping[str, Any]) -> float | None:
    tracks = row.get("relevant_enterprises", {}).get("tracks", {})
    values = [_number((tracks.get(name) or {}).get("value")) for name in ("woodworking", "metalworking")]
    # A missing track is unavailable, not a zero contribution to a complete
    # enterprise-base component.
    return sum(values) if all(value is not None for value in values) else None


def extract_groups(row: Mapping[str, Any]) -> dict[str, float | None]:
    investment = row.get("province_investment_momentum", {})
    current = investment.get("current_period", {})
    stock = investment.get("cumulative_stock", {})
    infrastructure = row.get("industrial_infrastructure_context", {})
    parks = row.get("industrial_park_context", {})
    return {
        "enterprise_base": _enterprise_total(row),
        # ``iip`` is a presentation field and may contain a legacy fallback.
        # The overall score accepts only the current-period indicator.
        "iip": _number(row.get("manufacturing_activity", {}).get("current_iip_yoy_pct")),
        "fdi_flow": _number(current.get("value")) if current.get("status") == "published" else None,
        "fdi_stock": _number(stock.get("value")) if stock.get("status") == "published" else None,
        "local_presence": _number(infrastructure.get("commune_ip_presence_rate_pct")),
        "local_park_count": _number(parks.get("industrial_park_count")),
    }


def score_rows(rows: Sequence[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    groups = {str(row.get("geo_unit_id")): extract_groups(row) for row in rows}
    peers = {name: [values.get(name) for values in groups.values()] for name in GROUP_WEIGHTS}
    result = {}
    for geo_id, values in groups.items():
        normalized = {name: _percentile(value, peers[name]) for name, value in values.items()}
        available = [(name, score, GROUP_WEIGHTS[name]) for name, score in normalized.items() if score is not None]
        total_weight = sum(weight for _, _, weight in available)
        score = None if not available else round(sum(score * weight for _, score, weight in available) / total_weight, 1)
        coverage = round(sum(weight for _, score, weight in available) / sum(GROUP_WEIGHTS.values()), 4)
        result[geo_id] = {
            "score": score,
            "evidence_coverage": round(coverage * 100, 1),
            "coverage": coverage,
            "available_groups": [name for name, _, _ in available],
            "missing_groups": [name for name in GROUP_WEIGHTS if name not in {item[0] for item in available}],
            "components": normalized,
            "score_type": "overall_city_evidence" if score is not None else "unavailable",
        }
    return result
