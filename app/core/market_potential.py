"""Pure policy for product-specific market-potential scoring.

Inputs are already normalized evidence. Fetching, persistence and scheduling
belong to outer layers; this module only makes deterministic decisions.
"""

from __future__ import annotations

from math import log
from typing import Any, Iterable, Mapping


K_DEFAULT = 20
COUNTRY_PRIOR_WEIGHT = 0.60
CITY_FIT_WEIGHT = 0.40
COUNTRY_WEIGHTS = {
    "hs_import": 0.35,
    "relevant_export": 0.20,
    "sector_consumption": 0.20,
    "manufacturing_growth": 0.10,
    "labor_cost_pressure": 0.10,
    "cement_consumption": 0.05,
}
SALES_WEIGHTS = {
    "rfq_count": 0.25,
    "quotation_response_rate": 0.20,
    "win_rate": 0.25,
    "avg_deal_value": 0.20,
    "repeat_purchase": 0.10,
}


def _bounded(value: Any) -> float | None:
    """Parse and clamp a normalized signal to the inclusive zero-to-one range."""
    if value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return max(0.0, min(1.0, number))


def percentile_rank(value: float | None, peers: Iterable[float | None]) -> float | None:
    """Return an inclusive percentile in [0, 1], ignoring missing peers."""
    current = _bounded(value)
    values = [_bounded(item) for item in peers]
    values = [item for item in values if item is not None]
    if current is None or not values:
        return None
    if len(values) == 1:
        return 1.0
    return sum(item <= current for item in values) / len(values)


def weighted_normalized_score(signals: Mapping[str, Any], weights: Mapping[str, float]) -> float | None:
    """Blend available normalized signals using only their corresponding weights."""
    available = [(key, _bounded(signals.get(key)), weight) for key, weight in weights.items()]
    available = [(key, value, weight) for key, value, weight in available if value is not None]
    if not available:
        return None
    denominator = sum(weight for _, _, weight in available)
    return round(sum(value * weight for _, value, weight in available) / denominator * 100, 4)


def country_product_prior(signals: Mapping[str, Any], category: str) -> float | None:
    """Score product demand from normalized country signals and category context."""
    if category not in {"woodworking", "metalworking"}:
        raise ValueError(f"unsupported product category: {category}")
    return weighted_normalized_score(signals, COUNTRY_WEIGHTS)


def minmax_normalize(values: Mapping[str, Any]) -> dict[str, float | None]:
    """Normalize an absolute signal across countries, preserving missing values."""
    parsed = {key: _number(value) for key, value in values.items()}
    present = [value for value in parsed.values() if value is not None]
    if not present:
        return {key: None for key in values}
    low, high = min(present), max(present)
    if low == high:
        return {key: (None if value is None else 1.0) for key, value in parsed.items()}
    return {key: (None if value is None else (value - low) / (high - low)) for key, value in parsed.items()}


def _number(value: Any) -> float | None:
    """Parse a finite numeric value while preserving missing or invalid inputs."""
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if number == number and abs(number) != float("inf") else None


def country_prior_snapshot(signals: Mapping[str, Any], category: str,
                           minimum_signals: int = 3) -> dict[str, Any]:
    """Score a country/product only when enough country evidence exists."""
    present = sum(_number(value) is not None for value in signals.values())
    score = country_product_prior(signals, category) if present >= minimum_signals else None
    return {"score": score, "data_coverage": round(present / len(COUNTRY_WEIGHTS), 4),
            "signal_count": present,
            "limitations": [] if score is not None else ["fewer_than_3_of_6_country_signals"]}


def city_fit_score(raw: Mapping[str, Any], peer_values: Iterable[float | None]) -> float | None:
    """Score city fit from business density, sector share, and peer ranking."""
    density = _bounded(raw.get("business_density_per_km2"))
    share = _bounded(raw.get("sector_relevant_business_share"))
    cluster = _bounded(raw.get("industrial_cluster_flag"))
    if density is None or share is None:
        return None
    raw_value = (density + share + (cluster or 0.0)) / (2.0 + (1.0 if cluster is not None else 0.0))
    return round((percentile_rank(raw_value, peer_values) or 0.0) * 100, 4)


def sales_validation_score(signals: Mapping[str, Any], peer_values: Iterable[float | None]) -> float | None:
    """Rank a weighted sales-validation signal against its peer cohort."""
    raw = weighted_normalized_score(signals, SALES_WEIGHTS)
    return None if raw is None else round((percentile_rank(raw / 100, peer_values) or 0.0) * 100, 4)


def blend_scores(country_prior: float | None, city_fit: float | None,
                 sales_score: float | None, rfq_count_12m: int,
                 k: int = K_DEFAULT) -> dict[str, Any]:
    """Blend external market evidence and internal sales validation by evidence strength."""
    """Blend evidence continuously; missing evidence never becomes an observed zero.

    The 60/40 country/city split is a tunable v1 default. When one external
    source is missing, the other is renormalized to 100% instead of treating
    the missing source as zero.
    """
    if k <= 0 or rfq_count_12m < 0:
        raise ValueError("k must be positive and RFQ count must not be negative")
    w_internal = min(1.0, log(1 + rfq_count_12m) / log(1 + k)) if sales_score is not None else 0.0
    external = [("city", city_fit, CITY_FIT_WEIGHT), ("country", country_prior, COUNTRY_PRIOR_WEIGHT)]
    available_external = [(name, value, weight) for name, value, weight in external if value is not None]
    external_weight = sum(weight for _, _, weight in available_external)
    w_city = (1.0 - w_internal) * next((weight / external_weight for name, _, weight in available_external if name == "city"), 0.0) if external_weight else 0.0
    w_country = (1.0 - w_internal) * next((weight / external_weight for name, _, weight in available_external if name == "country"), 0.0) if external_weight else 0.0
    components = [(sales_score, w_internal), (city_fit, w_city), (country_prior, w_country)]
    usable = [(value, weight) for value, weight in components if value is not None and weight > 0]
    score = None if not usable else round(sum(value * weight for value, weight in usable), 4)
    if score is None:
        score_type = "prior"
    elif w_internal > 0.5:
        score_type = "observed"
    elif w_city > 0:
        score_type = "estimated"
    else:
        score_type = "prior"
    return {"score": score, "score_type": score_type,
            "weights": {"internal": round(w_internal, 6), "city": round(w_city, 6), "country": round(w_country, 6)}}


def confidence(signal_groups: Mapping[str, Any], freshness: float | None,
               source_quality: float | None, internal_validation: bool) -> dict[str, Any]:
    """Estimate confidence from evidence coverage, freshness, quality, and validation."""
    """Return 0..1 confidence and explicit five-group coverage."""
    total = 5
    covered = sum(value is not None for value in signal_groups.values())
    coverage = covered / total
    freshness_value = _bounded(freshness) or 0.0
    quality_value = _bounded(source_quality) or 0.0
    score = 0.40 * coverage + 0.25 * freshness_value + 0.20 * quality_value + 0.15 * float(internal_validation)
    return {"confidence": round(score * 100, 4), "data_coverage": round(coverage, 4),
            "data_coverage_total": total}
