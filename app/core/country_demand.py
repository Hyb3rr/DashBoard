"""Deterministic country demand signal policy.

This module is deliberately storage and network independent.  Batch callers feed
normalized traffic observations; request handlers must consume persisted output.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from math import log1p
from typing import Any, Iterable

from .traffic_validity import evaluate_traffic_validity, normalize_traffic_evidence


@dataclass(frozen=True)
class CountryDemandConfig:
    min_sample_size: int = 100
    repeat_weight: float = 0.40
    depth_weight: float = 0.30
    product_weight: float = 0.20
    risk_weight: float = 0.10


def exclusion_state(event: dict[str, Any]) -> tuple[str | None, bool]:
    """Return (hard exclusion reason, soft risk flag) for one observation."""
    hard = (
        ("tor_exit", event.get("is_tor")),
        ("bot_scanner", event.get("bot_detected") or event.get("scanner_detected")),
        ("malicious_ip", event.get("malicious_ip") or event.get("threat_intel_hit")),
        ("datacenter_hosting", event.get("is_hosting") and not event.get("business_isp")),
    )
    for reason, matched in hard:
        if matched:
            return reason, False
    soft = bool(event.get("is_vpn") or event.get("is_proxy") or event.get("cgnat") or event.get("mobile_carrier"))
    return None, soft


def _identity(event: dict[str, Any], *keys: str) -> str | None:
    """Return the first declared non-empty identity from an event."""
    for key in keys:
        value = event.get(key)
        if value:
            return str(value)
    return None


def _identities(events: list[dict[str, Any]], *keys: str) -> set[str]:
    """Return declared identities only; never synthesize one from an IP."""
    return {identity for event in events if (identity := _identity(event, *keys)) is not None}


def aggregate_session_observations(events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse request observations without inventing session identities."""
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    request_index = 0
    for event in events:
        session_id = _identity(event, "session_id", "request_session_id")
        visitor_id = _identity(event, "visitor_id", "cookie_id", "fingerprint_id")
        if session_id:
            key = ("session", session_id)
        elif visitor_id:
            key = ("visitor", visitor_id)
        else:
            key = ("request_only", str(request_index))
            request_index += 1
        groups[key].append(dict(event))

    def first_known(rows: list[dict[str, Any]], field: str) -> Any:
        """Select the first available value for a grouped identity field."""
        return next((row[field] for row in rows if row.get(field) is not None), None)

    result: list[dict[str, Any]] = []
    for (identity_level, identity_value), rows in groups.items():
        session_id = identity_value if identity_level == "session" else None
        visitor_id = identity_value if identity_level == "visitor" else first_known(rows, "visitor_id")
        countries = {str(row.get("country_code") or "").upper() for row in rows if row.get("country_code")}
        item = dict(rows[0])
        item.update({
            "session_id": session_id,
            "visitor_id": visitor_id,
            "identity_level": identity_level,
            "request_count": len(rows),
            "engaged": any(row.get("engaged") is True for row in rows) if any(row.get("engaged") is not None for row in rows) else None,
            "engagement_seconds": max((float(row["engagement_seconds"]) for row in rows if row.get("engagement_seconds") is not None), default=None),
            "pageviews": max((int(row["pageviews"]) for row in rows if row.get("pageviews") is not None), default=None),
            "key_event_count": sum(int(row.get("key_event_count") or 0) for row in rows) if any(row.get("key_event_count") is not None for row in rows) else None,
            "geo_conflict": True if len(countries) > 1 else first_known(rows, "geo_conflict"),
            "country_code": first_known(rows, "country_code"),
        })
        item.update(normalize_traffic_evidence(item))
        item.update(evaluate_traffic_validity(item))
        result.append(item)
    return result


def _percentile_tier(value: float | None, values: list[float]) -> str:
    """Map a cohort value to its relative demand-volume tier."""
    if value is None or not values:
        return "UNKNOWN"
    ordered = sorted(values)
    rank = sum(item <= value for item in ordered) / len(ordered)
    return "HIGH" if rank >= .80 else "MEDIUM" if rank >= .40 else "LOW"


def _confidence(sample: int, config: CountryDemandConfig) -> str:
    """Classify sample confidence against the configured minimum size."""
    if sample < config.min_sample_size:
        return "—"
    if sample >= config.min_sample_size * 5:
        return "HIGH"
    return "MEDIUM"


def _signal(volume: str, quality: str, trend: str, sufficient: bool) -> str:
    """Derive a demand label from volume, quality and trend evidence."""
    if not sufficient:
        return "INSUFFICIENT_DATA"
    if volume == "LOW" and quality == "LOW":
        return "LIMITED"
    if trend == "RISING" and volume in {"LOW", "MEDIUM"}:
        return "WATCH"
    if quality == "HIGH" and trend in {"RISING", "STABLE"} and volume in {"MEDIUM", "HIGH"}:
        return "STRONG" if volume == "HIGH" else "RISING"
    if quality == "HIGH" and trend == "STABLE":
        return "STABLE"
    return "WATCH" if trend == "RISING" else "LIMITED"


def _demand_strength(weighted: float, reference: float = 100.0) -> float:
    """Compress weighted demand into a bounded logarithmic score."""
    if weighted <= 0:
        return 0.0
    return round(min(100.0, 100.0 * log1p(weighted) / log1p(reference)), 2)


def _usable_demand_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep only qualified or suspect events with numeric validity evidence."""
    return [
        event for event in events
        if event.get("traffic_status") in {"qualified", "suspect"}
        and isinstance(event.get("traffic_validity_score"), (int, float))
    ]


def _engagement_components(events: list[dict[str, Any]]) -> tuple[float | None, float]:
    """Calculate engagement quality and the share of events with engagement evidence."""
    evidence_keys = ("engaged", "engagement_seconds", "pageviews", "key_event_count")
    rows = [event for event in events if any(event.get(key) is not None for key in evidence_keys)]
    if not rows:
        return None, 0.0
    sample_count = len(rows)
    engaged_rate = sum(bool(event.get("engaged")) for event in rows) / sample_count
    page_depth = sum(min(float(event.get("pageviews") or 0) / 5.0, 1.0) for event in rows) / sample_count
    key_event_rate = sum(bool(event.get("key_event_count")) for event in rows) / sample_count
    quality = round(100.0 * (0.45 * engaged_rate + 0.30 * page_depth + 0.25 * key_event_rate), 2)
    return quality, round(sample_count / len(events), 4) if events else 0.0


def _momentum_components(weighted: float, previous_weighted: float) -> tuple[float | None, float | None]:
    """Calculate period-over-period growth and its bounded momentum score."""
    if previous_weighted <= 0:
        return None, None
    growth = (weighted - previous_weighted) / previous_weighted * 100.0
    return growth, round(max(0.0, min(100.0, 50.0 + growth)), 2)


def _combined_demand_score(strength: float, quality: float | None, momentum: float | None) -> float:
    """Blend available demand components and renormalize their configured weights."""
    weighted_components = [(0.50, strength)]
    weighted_components.extend((weight, value) for weight, value in ((0.30, quality), (0.20, momentum)) if value is not None)
    return round(sum(weight * value for weight, value in weighted_components) / sum(weight for weight, _ in weighted_components), 2)


def _country_demand_components(events: list[dict[str, Any]], previous_events: list[dict[str, Any]]) -> dict[str, Any]:
    """Calculate weighted demand, engagement quality, momentum and confidence."""
    usable = _usable_demand_events(events)
    weighted = sum(float(event["traffic_validity_score"]) for event in usable)
    previous_usable = _usable_demand_events(previous_events)
    previous_weighted = sum(float(event["traffic_validity_score"]) for event in previous_usable)
    engagement_quality, engagement_coverage = _engagement_components(usable)
    growth, momentum = _momentum_components(weighted, previous_weighted)
    sample_damping = min(1.0, log1p(min(weighted, previous_weighted)) / log1p(30.0)) if previous_weighted > 0 else 0.0
    demand_confidence = round(engagement_coverage * sample_damping, 4)
    strength = _demand_strength(weighted)
    return {
        "weighted_qualified_sessions": round(weighted, 4),
        "previous_weighted_qualified_sessions": round(previous_weighted, 4),
        "demand_strength_score": strength,
        "engagement_quality_score": engagement_quality,
        "engagement_evidence_coverage": engagement_coverage,
        "momentum_score": momentum,
        "momentum_pct": round(growth, 2) if growth is not None else None,
        "country_demand_score": _combined_demand_score(strength, engagement_quality, momentum),
        "demand_confidence": demand_confidence,
        "demand_reason": (
            f"Demand strength {strength:.1f}; engagement coverage {engagement_coverage:.0%}; momentum {momentum:.1f}."
            if momentum is not None else
            f"Demand strength {strength:.1f}; engagement coverage {engagement_coverage:.0%}; momentum unavailable."
        ),
    }


def _bucket_current_event(event: dict[str, Any], buckets: dict[str, Any]) -> None:
    """Apply current-period exclusion and validity evidence to its country bucket."""
    code = str(event.get("country_code") or "").upper()
    if not code:
        return
    reason, soft = exclusion_state(event)
    status = "excluded" if reason else event.get("traffic_status") or "unknown"
    if status not in {"qualified", "suspect", "excluded", "unknown"}:
        status = "unknown"
    bucket = buckets[code]
    bucket["validity"][status] += 1
    score = event.get("traffic_validity_score")
    if status in {"qualified", "suspect"} and isinstance(score, (int, float)) and 0 <= float(score) <= 1:
        bucket["validity_scores"].append(float(score))
        bucket["validity"]["weighted"] += float(score)
    confidence = event.get("validity_confidence")
    if isinstance(confidence, (int, float)) and 0 <= float(confidence) <= 1:
        bucket["confidence_scores"].append(float(confidence))
    if reason:
        bucket["excluded"][reason] += 1
        return
    qualified = dict(event)
    qualified["risk_flag"] = soft
    bucket["qualified"].append(qualified)


def _bucket_previous_event(event: dict[str, Any], previous: dict[str, list[dict[str, Any]]]) -> None:
    """Add a non-excluded prior-period event for trend comparison."""
    code = str(event.get("country_code") or "").upper()
    if not code:
        return
    reason, soft = exclusion_state(event)
    if reason:
        return
    qualified = dict(event)
    qualified["risk_flag"] = soft
    previous[code].append(qualified)


def _collect_country_buckets(current_events, previous_events):
    """Group current validity counts and prior trend evidence by country."""
    buckets: dict[str, dict[str, Any]] = defaultdict(lambda: {"qualified": [], "excluded": defaultdict(int), "validity": defaultdict(float), "validity_scores": [], "confidence_scores": []})
    previous: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in current_events:
        _bucket_current_event(event, buckets)
    for event in previous_events:
        _bucket_previous_event(event, previous)
    return buckets, previous


def _country_behavior_metrics(events: list[dict[str, Any]], config: CountryDemandConfig) -> dict[str, Any]:
    """Summarize identity, repeat visits, product interest, and quality for one country."""
    visitor_ids = [_identity(event, "visitor_id", "cookie_id", "fingerprint_id") for event in events]
    visitor_counts = Counter(identity for identity in visitor_ids if identity is not None)
    sessions = _identities(events, "session_id", "request_session_id")
    organizations = _identities(events, "organization_id", "asn")
    depths = [float(event.get("engaged_session_depth", 0) or 0) for event in events]
    product_visitors = {
        identity for event, identity in zip(events, visitor_ids)
        if event.get("product_page") and identity is not None
    }
    visitor_count = len(visitor_counts)
    identity_coverage = sum(identity is not None for identity in visitor_ids) / len(events) if events else 0.0
    repeat_rate = sum(count > 1 for count in visitor_counts.values()) / visitor_count if visitor_count else 0.0
    average_depth = min(sum(depths) / len(depths) / 5.0, 1.0) if depths else 0.0
    product_ratio = len(product_visitors) / visitor_count if visitor_count else 0.0
    risk_rate = sum(bool(event.get("risk_flag")) for event in events) / len(events) if events else 0.0
    quality = (
        config.repeat_weight * repeat_rate
        + config.depth_weight * average_depth
        + config.product_weight * product_ratio
        + config.risk_weight * (1 - risk_rate)
    )
    return {
        "qualified_sessions": len(sessions),
        "qualified_visitors": visitor_count,
        "unique_organizations": len(organizations),
        "repeat_visitors": sum(count > 1 for count in visitor_counts.values()),
        "depths": depths,
        "product_page_visitors": len(product_visitors),
        "identity_coverage": identity_coverage,
        "quality_score": quality,
    }


def _country_trend_metrics(
    qualified_sessions: int,
    identity_coverage: float,
    previous_events: list[dict[str, Any]],
    config: CountryDemandConfig,
) -> dict[str, Any]:
    """Calculate prior-session count and sample-gated country trend."""
    previous_count = len(_identities(previous_events, "session_id", "request_session_id"))
    sufficient = (
        qualified_sessions >= config.min_sample_size
        and previous_count >= config.min_sample_size
        and identity_coverage == 1.0
    )
    trend_pct = (qualified_sessions - previous_count) / previous_count * 100 if sufficient and previous_count else None
    if trend_pct is None:
        trend = "INSUFFICIENT_DATA"
    elif trend_pct > 20:
        trend = "RISING"
    elif trend_pct < -10:
        trend = "DECLINING"
    else:
        trend = "STABLE"
    return {"previous_sessions": previous_count, "trend_pct": trend_pct, "trend": trend}


def _validity_metrics(bucket: dict[str, Any]) -> dict[str, Any]:
    """Summarize raw traffic validity counts, coverage, and available averages."""
    validity = bucket["validity"]
    total = sum(validity[key] for key in ("qualified", "suspect", "excluded", "unknown"))
    covered = validity["qualified"] + validity["suspect"] + validity["excluded"]
    scores = bucket["validity_scores"]
    confidences = bucket["confidence_scores"]
    return {
        "raw_sessions": int(total),
        "qualified_sessions_count": int(validity["qualified"]),
        "suspect_sessions_count": int(validity["suspect"]),
        "excluded_sessions_count": int(validity["excluded"]),
        "unknown_sessions_count": int(validity["unknown"]),
        "weighted_qualified_sessions": round(validity["weighted"], 4),
        "evidence_coverage": round(covered / total, 4) if total else 0.0,
        "avg_validity_score": round(sum(scores) / len(scores), 4) if scores else None,
        "avg_validity_confidence": round(sum(confidences) / len(confidences), 4) if confidences else None,
    }


def _country_snapshot_row(code: str, bucket: dict[str, Any], previous: dict[str, list[dict[str, Any]]], config: CountryDemandConfig) -> dict[str, Any]:
    """Build one country row from behavior, trend, validity, and demand evidence."""
    events = bucket["qualified"]
    behavior = _country_behavior_metrics(events, config)
    trend = _country_trend_metrics(behavior["qualified_sessions"], behavior["identity_coverage"], previous.get(code, []), config)
    return {
        "country_code": code,
        "qualified_requests": len(events),
        "qualified_sessions": behavior["qualified_sessions"],
        "qualified_visitors": behavior["qualified_visitors"],
        "unique_organizations": behavior["unique_organizations"],
        "identity_coverage": round(behavior["identity_coverage"], 4),
        "repeat_visitors": behavior["repeat_visitors"],
        "avg_engaged_sessions": round(sum(behavior["depths"]) / len(behavior["depths"]), 2) if behavior["depths"] else 0.0,
        "product_page_visitors": behavior["product_page_visitors"],
        "quality_score": round(behavior["quality_score"], 4),
        "trend_pct": round(trend["trend_pct"], 2) if trend["trend_pct"] is not None else None,
        "trend": trend["trend"],
        "excluded": dict(bucket["excluded"]),
        **_validity_metrics(bucket),
        **_country_demand_components(events, previous.get(code, [])),
    }


def _add_cohort_signals(rows: list[dict[str, Any]], config: CountryDemandConfig) -> None:
    """Attach relative volume, quality, confidence, and explanation labels to rows."""
    volumes = [float(row["qualified_sessions"]) for row in rows]
    for row in rows:
        row["volume_tier"] = _percentile_tier(float(row["qualified_sessions"]), volumes)
        row["quality_tier"] = "HIGH" if row["quality_score"] >= .7 else "MEDIUM" if row["quality_score"] >= .4 else "LOW"
        row["sample_size_sufficient"] = row["trend_pct"] is not None
        row["confidence"] = _confidence(row["qualified_sessions"], config)
        row["signal"] = _signal(row["volume_tier"], row["quality_tier"], row["trend"], row["sample_size_sufficient"])
        row["explanation"] = (
            "Insufficient sample for a reliable trend."
            if not row["sample_size_sufficient"] else
            f"{row['trend_pct']:+.1f}% qualified traffic vs previous period; {row['repeat_visitors']} repeat visitors and {row['product_page_visitors']} product-page visitors."
        )


def aggregate_country_demand(
    current_events: Iterable[dict[str, Any]],
    previous_events: Iterable[dict[str, Any]],
    *,
    period: str = "30d",
    config: CountryDemandConfig | None = None,
) -> dict[str, Any]:
    """Build a versioned, JSON-safe country demand snapshot from batch input."""
    config = config or CountryDemandConfig()
    buckets, previous = _collect_country_buckets(current_events, previous_events)
    rows = [_country_snapshot_row(code, bucket, previous, config) for code, bucket in buckets.items()]
    _add_cohort_signals(rows, config)
    countries = sorted(rows, key=lambda row: (-row["qualified_sessions"], row["country_code"]))
    return {"period": period, "min_sample_threshold": config.min_sample_size, "countries": countries}


EVIDENCE_LEVELS = ((0, "NONE", 0.0), (1, "VERY_LOW", 0.10), (10, "LOW", 0.25), (30, "MEDIUM", 0.60), (100, "HIGH", 1.0))


def _evidence_level(traffic: int) -> tuple[str, float]:
    """Map observed qualified traffic volume to an evidence tier."""
    level, factor = "NONE", 0.0
    for minimum, candidate, confidence in EVIDENCE_LEVELS:
        if traffic >= minimum:
            level, factor = candidate, confidence
    return level, factor


def _opportunity_state(traffic: int, market_score: float | None, evidence_level: str, traffic_strength: float) -> str:
    """Choose a traffic-context state without inventing market evidence."""
    if traffic <= 0:
        return "WATCH"
    if evidence_level in {"VERY_LOW", "LOW"}:
        return "EMERGING" if market_score is not None and market_score >= 75 else "WATCH"
    if market_score is not None and market_score >= 75 and evidence_level in {"MEDIUM", "HIGH"}:
        return "PRIORITIZE"
    if traffic_strength >= 60:
        return "INVESTIGATE"
    return "EMERGING"


def _opportunity_status(market: float | None, demand: float | None, confidence: float | None, opportunity: float | None) -> str:
    """Classify opportunity using market score and confidence-adjusted demand."""
    if opportunity is None or market is None or demand is None:
        return "WATCH"
    confidence = float(confidence or 0.0)
    if opportunity >= 70 and confidence >= 0.60 and demand >= 60:
        return "PRIORITIZE"
    if market >= 70 and demand > 50 and confidence < 0.60:
        return "EMERGING"
    if demand >= 70 and market < 70:
        return "INVESTIGATE"
    return "WATCH" if opportunity >= 55 else "LOW_PRIORITY"


def _opportunity_demand_metrics(demand, observed_values):
    """Calculate traffic rank and available quality metrics for one country."""
    traffic = int(demand.get("qualified_requests", 0) or 0)
    evidence, confidence = _evidence_level(traffic)
    rank = sum(value <= traffic for value in observed_values) / len(observed_values) * 100 if observed_values else 0.0
    quality = float(demand.get("quality_score", 0) or 0) * 100 if float(demand.get("identity_coverage", 0) or 0) > 0 else None
    return traffic, evidence, confidence, rank, quality, demand.get("trend_pct")


def _opportunity_scores(market_score: float | None, demand: dict[str, Any]) -> tuple[Any, float | None, float | None]:
    """Calculate confidence-adjusted demand and the combined opportunity score."""
    country_demand = demand.get("country_demand_score")
    confidence = demand.get("demand_confidence")
    adjusted = round(50.0 + float(confidence or 0.0) * (float(country_demand) - 50.0), 1) if isinstance(country_demand, (int, float)) else None
    opportunity = round(0.60 * market_score + 0.40 * adjusted, 1) if market_score is not None and adjusted is not None else None
    return country_demand, adjusted, opportunity


def _recent_traffic_metrics(periods: dict[str, Any], code: str) -> tuple[int, int, float | None]:
    """Return short- and long-window traffic with their observed share."""
    traffic_7d = int(periods.get("7d", {}).get(code, {}).get("qualified_requests", 0) or 0)
    traffic_90d = int(periods.get("90d", {}).get(code, {}).get("qualified_requests", 0) or 0)
    share = round(traffic_7d / traffic_90d * 100, 1) if traffic_90d else None
    return traffic_7d, traffic_90d, share


def _opportunity_explanation(
    traffic: int,
    period: str,
    market_score: float | None,
    adjusted_demand: float | None,
    country_demand: Any,
    demand_confidence: Any,
    opportunity: float | None,
    status: str,
) -> str:
    """Explain score availability or summarize the evidence behind a score."""
    if market_score is None:
        return f"{traffic} qualified requests observed in {period}. Market score unavailable."
    if adjusted_demand is None:
        return f"{traffic} qualified requests observed in {period}. Market score or demand unavailable."
    evidence_quality = "sufficient" if float(demand_confidence or 0.0) >= 0.60 else "limited"
    return (
        f"Market Score {market_score:.1f}; Demand Score {float(country_demand):.1f}; "
        f"Demand Confidence {float(demand_confidence or 0.0):.0%}; Adjusted Demand {adjusted_demand:.1f}; "
        f"Opportunity {opportunity:.1f}. Status {status}; demand evidence is {evidence_quality}."
    )


def _country_opportunity_row(code, demand, periods, market_scores, observed_values, period):
    """Build one country opportunity row from demand and market snapshots."""
    market = market_scores.get(code, {})
    raw_market = market.get("market_score")
    market_score = float(raw_market) if isinstance(raw_market, (int, float)) else None
    traffic, evidence, confidence, rank, quality, trend = _opportunity_demand_metrics(demand, observed_values)
    demand_confidence = demand.get("demand_confidence")
    country_demand, adjusted_demand, opportunity = _opportunity_scores(market_score, demand)
    traffic_7d, traffic_90d, recent_share = _recent_traffic_metrics(periods, code)
    state = _opportunity_state(traffic, market_score, evidence, rank)
    status = _opportunity_status(market_score, country_demand, demand_confidence, opportunity)
    name = market.get("country_name") or demand.get("country_name") or code
    explanation = _opportunity_explanation(
        traffic, period, market_score, adjusted_demand, country_demand,
        demand_confidence, opportunity, status,
    )
    return {
        "country_code": code, "country_name": name, "market_score": market_score,
        "opportunity_score": opportunity, "opportunity_state": state,
        "country_demand_score": country_demand, "demand_confidence": demand_confidence,
        "weighted_qualified_sessions": demand.get("weighted_qualified_sessions"),
        "evidence_coverage": demand.get("evidence_coverage"),
        "adjusted_demand_score": adjusted_demand, "opportunity_status": status,
        "opportunity_reason": explanation, "traffic_7d": traffic_7d,
        "traffic_30d": traffic, "traffic_90d": traffic_90d,
        "recent_traffic_share_pct": recent_share,
        "trend_pct": round(float(trend), 2) if trend is not None else None,
        "evidence_level": evidence, "evidence_confidence": confidence,
        "traffic_strength": round(rank, 1),
        "quality_score": round(quality, 1) if quality is not None else None,
        "explanation": explanation,
    }


def build_country_opportunities(
    snapshots: dict[str, dict[str, Any] | None],
    market_scores: dict[str, dict[str, Any]],
    period: str = "30d",
) -> dict[str, Any]:
    """Join traffic snapshots with market context while preserving missing demand evidence."""
    if period not in {"7d", "30d", "90d"}:
        raise ValueError("unsupported country demand period")
    by_period = {
        snapshot_period: {
            str(item.get("country_code") or "").upper(): item
            for item in (snapshot or {}).get("countries", [])
        }
        for snapshot_period, snapshot in snapshots.items()
    }
    selected = by_period.get(period, {})
    codes = {code for code, row in selected.items() if code and int(row.get("qualified_requests", 0) or 0) > 0}
    observed_values = sorted(int(selected[code].get("qualified_requests", 0) or 0) for code in codes)
    countries = [
        _country_opportunity_row(code, selected[code], by_period, market_scores, observed_values, period)
        for code in sorted(codes)
    ]
    countries.sort(key=lambda item: (-(item["opportunity_score"] if item["opportunity_score"] is not None else -1), item["country_name"]))
    return {"period": period, "countries": countries}


__all__ = ["CountryDemandConfig", "aggregate_country_demand", "build_country_opportunities", "exclusion_state"]
