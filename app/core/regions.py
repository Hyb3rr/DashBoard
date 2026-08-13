"""Region-context normalization and precomputed market result access."""

from __future__ import annotations

from typing import Any


SEVERITY_LEVELS = {"low", "medium", "high", "critical"}
MARKET_POINTS = {"low": 25, "medium": 50, "high": 75, "very_high": 100}


def normalise_economic_indicators(value: Any) -> dict:
    """Return the v1 object contract while tolerating the legacy list seed."""
    if isinstance(value, dict):
        result = dict(value)
        result.setdefault("schema_version", 1)
        result.setdefault("indicators", {})
        result.setdefault("trade", {})
        return result
    if not isinstance(value, list):
        value = []
    indicators = {}
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            continue
        label = str(item.get("label") or item.get("name") or f"indicator_{index}")
        key = "_".join(part for part in label.lower().replace("%", "percent").split() if part)
        key = key or f"indicator_{index}"
        indicators[key] = dict(item)
    return {"schema_version": 0, "indicators": indicators, "trade": {}}


def _legacy_conflict_type(description: str | None) -> str:
    """Map legacy descriptions without using country identity."""
    value = (description or "").lower()
    if "no active" in value or value.strip() == "none":
        return "none"
    if "active interstate war" in value:
        return "interstate_war"
    if "active civil war" in value:
        return "civil_war"
    if "elevated" in value or "geopolitical conflict" in value or "tension" in value:
        return "elevated_tension"
    return "unknown"


def _normalise_severity(value: Any, indicator_type: str) -> str | None:
    if isinstance(value, str):
        level = value.strip().lower()
        if level in SEVERITY_LEVELS:
            return level
        try:
            value = int(level)
        except ValueError:
            return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        number = int(value)
        if number <= 1:
            return "low"
        if number <= 3:
            return "medium"
        if number == 4:
            return "high"
        return "critical"
    return {
        "none": "low",
        "elevated_tension": "medium",
        "interstate_war": "critical",
        "civil_war": "critical",
    }.get(indicator_type)


def normalise_conflict_indicator(item: Any) -> dict | None:
    """Return one canonical indicator plus legacy response aliases."""
    if item is None:
        return None
    if isinstance(item, dict):
        original = dict(item)
    elif isinstance(item, str):
        original = {"description": item}
    else:
        return None

    description = original.get("description") or original.get("value")
    description = str(description).strip() if description not in (None, "") else None
    indicator_type = str(original.get("type") or "").strip().lower()
    if not indicator_type:
        indicator_type = _legacy_conflict_type(description)
    severity = _normalise_severity(original.get("severity"), indicator_type)
    date = original.get("date") or original.get("data_date")

    result = {
        key: value
        for key, value in original.items()
        if key not in {"type", "severity", "source", "date", "description", "source_url", "confidence"}
    }
    result.update({
        "type": indicator_type or "unknown",
        "severity": severity,
        "source": original.get("source"),
        "date": date,
        "description": description,
        "source_url": original.get("source_url"),
        "confidence": original.get("confidence"),
        # Legacy aliases remain available to existing API consumers.
        "label": original.get("label") or "Conflict indicator",
        "value": description,
        "data_date": date,
    })
    return result


def normalise_conflict_indicators(items: Any) -> list[dict]:
    if items is None:
        return []
    if not isinstance(items, list):
        items = [items]
    return [normalised for item in items if (normalised := normalise_conflict_indicator(item)) is not None]


def market_score(region_profile: dict | None) -> dict:
    """Read the batch-precomputed result; never calculate request-time percentiles."""
    profile = region_profile or {}
    economic = normalise_economic_indicators(profile.get("economic_indicators"))
    result = {
        "market_score": economic.get("market_score", profile.get("market_score")),
        "market_level": economic.get("market_level", profile.get("market_level", "unknown")),
        "market_components": economic.get("market_components", profile.get("market_components", {})),
        "market_evidence": economic.get("market_evidence", profile.get("market_evidence", [])),
        "product_opportunities": economic.get("product_opportunities", profile.get("product_opportunities", [])),
    }
    if result["market_score"] is None and economic.get("schema_version") == 0:
        # Transitional read support for the existing seed until market_refresh runs.
        legacy = [item for item in economic["indicators"].values() if isinstance(item, dict)]
        old = {str(item.get("market_signal", "")).lower(): item for item in legacy}
        weights = {"market_capacity": 0.5, "demand_fit": 0.5}
        parts = []
        total = present = 0.0
        for signal, weight in weights.items():
            item = old.get(signal)
            tier = str(item.get("market_tier", "")).lower() if item else ""
            if tier not in MARKET_POINTS:
                continue
            points = MARKET_POINTS[tier]
            parts.append({"signal": "product_demand" if signal == "demand_fit" else signal,
                          "value": tier, "points": points, "weight": weight,
                          "effect": round(points * weight, 2), "source": item.get("source"),
                          "date": item.get("date") or item.get("data_date")})
            total += points * weight
            present += weight
        if present:
            score = round(total / present)
            result.update({"market_score": score,
                           "market_level": "low" if score <= 24 else "medium" if score <= 49 else "high" if score <= 74 else "very_high",
                           "market_evidence": parts})
    return result
