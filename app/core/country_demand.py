"""Deterministic country demand signal policy.

This module is deliberately storage and network independent.  Batch callers feed
normalized traffic observations; request handlers must consume persisted output.
"""

from __future__ import annotations

from collections import defaultdict
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
    if value is None or not values:
        return "UNKNOWN"
    ordered = sorted(values)
    rank = sum(item <= value for item in ordered) / len(ordered)
    return "HIGH" if rank >= .80 else "MEDIUM" if rank >= .40 else "LOW"


def _confidence(sample: int, config: CountryDemandConfig) -> str:
    if sample < config.min_sample_size:
        return "—"
    if sample >= config.min_sample_size * 5:
        return "HIGH"
    return "MEDIUM"


def _signal(volume: str, quality: str, trend: str, sufficient: bool) -> str:
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
    if weighted <= 0:
        return 0.0
    return round(min(100.0, 100.0 * log1p(weighted) / log1p(reference)), 2)


def _country_demand_components(events: list[dict[str, Any]], previous_events: list[dict[str, Any]]) -> dict[str, Any]:
    usable = [event for event in events if event.get("traffic_status") in {"qualified", "suspect"} and isinstance(event.get("traffic_validity_score"), (int, float))]
    weighted = sum(float(event["traffic_validity_score"]) for event in usable)
    previous_usable = [event for event in previous_events if event.get("traffic_status") in {"qualified", "suspect"} and isinstance(event.get("traffic_validity_score"), (int, float))]
    previous_weighted = sum(float(event["traffic_validity_score"]) for event in previous_usable)
    engagement_rows = [event for event in usable if any(event.get(key) is not None for key in ("engaged", "engagement_seconds", "pageviews", "key_event_count"))]
    engaged_rate = sum(bool(event.get("engaged")) for event in engagement_rows) / len(engagement_rows) if engagement_rows else 0.0
    depth = sum(min(float(event.get("pageviews") or 0) / 5.0, 1.0) for event in engagement_rows) / len(engagement_rows) if engagement_rows else 0.0
    key_rate = sum(bool(event.get("key_event_count")) for event in engagement_rows) / len(engagement_rows) if engagement_rows else 0.0
    engagement_quality = round(100.0 * (0.45 * engaged_rate + 0.30 * depth + 0.25 * key_rate), 2) if engagement_rows else None
    engagement_coverage = round(len(engagement_rows) / len(usable), 4) if usable else 0.0
    growth = ((weighted - previous_weighted) / previous_weighted * 100.0) if previous_weighted > 0 else None
    momentum = round(max(0.0, min(100.0, 50.0 + (growth or 0.0))), 2) if growth is not None else None
    sample_damping = min(1.0, log1p(min(weighted, previous_weighted)) / log1p(30.0)) if previous_weighted > 0 else 0.0
    demand_confidence = round(engagement_coverage * sample_damping, 4)
    available = [0.50 * _demand_strength(weighted)]
    if engagement_quality is not None:
        available.append(0.30 * engagement_quality)
    if momentum is not None:
        available.append(0.20 * momentum)
    demand_score = round(sum(available) / (0.50 + (0.30 if engagement_quality is not None else 0.0) + (0.20 if momentum is not None else 0.0)), 2)
    return {"weighted_qualified_sessions": round(weighted, 4), "previous_weighted_qualified_sessions": round(previous_weighted, 4), "demand_strength_score": _demand_strength(weighted), "engagement_quality_score": engagement_quality, "engagement_evidence_coverage": engagement_coverage, "momentum_score": momentum, "momentum_pct": round(growth, 2) if growth is not None else None, "country_demand_score": demand_score, "demand_confidence": demand_confidence, "demand_reason": f"Demand strength {_demand_strength(weighted):.1f}; engagement coverage {engagement_coverage:.0%}; momentum {momentum:.1f}." if momentum is not None else f"Demand strength {_demand_strength(weighted):.1f}; engagement coverage {engagement_coverage:.0%}; momentum unavailable."}


def aggregate_country_demand(
    current_events: Iterable[dict[str, Any]],
    previous_events: Iterable[dict[str, Any]],
    *,
    period: str = "30d",
    config: CountryDemandConfig | None = None,
) -> dict[str, Any]:
    """Build a versioned, JSON-safe country demand snapshot from batch input."""
    config = config or CountryDemandConfig()
    buckets: dict[str, dict[str, Any]] = defaultdict(lambda: {"qualified": [], "excluded": defaultdict(int), "validity": defaultdict(float), "validity_scores": [], "confidence_scores": []})
    previous: dict[str, list[dict[str, Any]]] = defaultdict(list)

    def consume(events: Iterable[dict[str, Any]], target: dict[str, Any], keep_previous: bool = False) -> None:
        for event in events:
            code = str(event.get("country_code") or "").upper()
            if not code:
                continue
            reason, soft = exclusion_state(event)
            status = "excluded" if reason else event.get("traffic_status") or "unknown"
            if status not in {"qualified", "suspect", "excluded", "unknown"}:
                status = "unknown"
            target[code]["validity"][status] += 1
            score = event.get("traffic_validity_score")
            if status in {"qualified", "suspect"} and isinstance(score, (int, float)) and 0 <= float(score) <= 1:
                target[code]["validity_scores"].append(float(score))
                target[code]["validity"]["weighted"] += float(score)
            confidence = event.get("validity_confidence")
            if isinstance(confidence, (int, float)) and 0 <= float(confidence) <= 1:
                target[code]["confidence_scores"].append(float(confidence))
            if reason:
                target[code]["excluded"][reason] += 1
                continue
            item = dict(event)
            item["risk_flag"] = soft
            target[code]["qualified"].append(item)

    consume(current_events, buckets)
    for event in previous_events:
        code = str(event.get("country_code") or "").upper()
        if code:
            reason, soft = exclusion_state(event)
            if not reason:
                item = dict(event)
                item["risk_flag"] = soft
                previous[code].append(item)

    raw: list[dict[str, Any]] = []
    for code, bucket in buckets.items():
        events = bucket["qualified"]
        sessions = _identities(events, "session_id", "request_session_id")
        visitors = _identities(events, "visitor_id", "cookie_id", "fingerprint_id")
        orgs = _identities(events, "organization_id", "asn")
        repeat_visitors = sum(1 for visitor in visitors if sum(_identity(e, "visitor_id", "cookie_id", "fingerprint_id") == visitor for e in events) > 1)
        depth = [float(e.get("engaged_session_depth", 0) or 0) for e in events]
        product_visitors = {_identity(e, "visitor_id", "cookie_id", "fingerprint_id") for e in events if e.get("product_page")}
        product_visitors.discard(None)
        qualified_sessions = len(sessions)
        visitor_count = len(visitors)
        identity_events = sum(1 for e in events if _identity(e, "visitor_id", "cookie_id", "fingerprint_id") is not None)
        identity_coverage = identity_events / len(events) if events else 0.0
        repeat_rate = repeat_visitors / visitor_count if visitor_count else 0.0
        avg_depth = min(sum(depth) / len(depth) / 5.0, 1.0) if depth else 0.0
        product_ratio = len(product_visitors) / visitor_count if visitor_count else 0.0
        risk_rate = sum(bool(e.get("risk_flag")) for e in events) / len(events) if events else 0.0
        quality = config.repeat_weight * repeat_rate + config.depth_weight * avg_depth + config.product_weight * product_ratio + config.risk_weight * (1 - risk_rate)
        prev_events = previous.get(code, [])
        prev_sessions = _identities(prev_events, "session_id", "request_session_id")
        prev_count = len(prev_sessions)
        sufficient = (qualified_sessions >= config.min_sample_size and prev_count >= config.min_sample_size
                      and identity_coverage == 1.0)
        trend_pct = ((qualified_sessions - prev_count) / prev_count * 100) if sufficient and prev_count else None
        trend = "RISING" if trend_pct is not None and trend_pct > 20 else "DECLINING" if trend_pct is not None and trend_pct < -10 else "STABLE" if trend_pct is not None else "INSUFFICIENT_DATA"
        validity = bucket["validity"]
        demand_components = _country_demand_components(events, prev_events)
        total_sessions = sum(validity[key] for key in ("qualified", "suspect", "excluded", "unknown"))
        raw.append({"country_code": code, "qualified_requests": len(events), "qualified_sessions": qualified_sessions, "qualified_visitors": visitor_count, "unique_organizations": len(orgs), "identity_coverage": round(identity_coverage, 4), "repeat_visitors": repeat_visitors, "avg_engaged_sessions": round(sum(depth) / len(depth), 2) if depth else 0.0, "product_page_visitors": len(product_visitors), "quality_score": round(quality, 4), "trend_pct": round(trend_pct, 2) if trend_pct is not None else None, "trend": trend, "excluded": dict(bucket["excluded"]), "raw_sessions": int(total_sessions), "qualified_sessions_count": int(validity["qualified"]), "suspect_sessions_count": int(validity["suspect"]), "excluded_sessions_count": int(validity["excluded"]), "unknown_sessions_count": int(validity["unknown"]), "weighted_qualified_sessions": round(validity["weighted"], 4), "evidence_coverage": round((validity["qualified"] + validity["suspect"] + validity["excluded"]) / total_sessions, 4) if total_sessions else 0.0, "avg_validity_score": round(sum(bucket["validity_scores"]) / len(bucket["validity_scores"]), 4) if bucket["validity_scores"] else None, "avg_validity_confidence": round(sum(bucket["confidence_scores"]) / len(bucket["confidence_scores"]), 4) if bucket["confidence_scores"] else None, **demand_components})

    volume_values = [float(item["qualified_sessions"]) for item in raw]
    for item in raw:
        item["volume_tier"] = _percentile_tier(float(item["qualified_sessions"]), volume_values)
        item["quality_tier"] = "HIGH" if item["quality_score"] >= .7 else "MEDIUM" if item["quality_score"] >= .4 else "LOW"
        item["sample_size_sufficient"] = item["trend_pct"] is not None
        item["confidence"] = _confidence(item["qualified_sessions"], config)
        item["signal"] = _signal(item["volume_tier"], item["quality_tier"], item["trend"], item["sample_size_sufficient"])
        item["explanation"] = "Insufficient sample for a reliable trend." if not item["sample_size_sufficient"] else f"{item['trend_pct']:+.1f}% qualified traffic vs previous period; {item['repeat_visitors']} repeat visitors and {item['product_page_visitors']} product-page visitors."
    return {"period": period, "min_sample_threshold": config.min_sample_size, "countries": sorted(raw, key=lambda item: (-item["qualified_sessions"], item["country_code"]))}


EVIDENCE_LEVELS = ((0, "NONE", 0.0), (1, "VERY_LOW", 0.10), (10, "LOW", 0.25), (30, "MEDIUM", 0.60), (100, "HIGH", 1.0))


def _evidence_level(traffic: int) -> tuple[str, float]:
    level, factor = "NONE", 0.0
    for minimum, candidate, confidence in EVIDENCE_LEVELS:
        if traffic >= minimum:
            level, factor = candidate, confidence
    return level, factor


def _opportunity_state(traffic: int, market_score: float | None, evidence_level: str, traffic_strength: float) -> str:
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


def build_country_opportunities(
    snapshots: dict[str, dict[str, Any] | None],
    market_scores: dict[str, dict[str, Any]],
    period: str = "30d",
) -> dict[str, Any]:
    """Join persisted traffic snapshots with existing market context.

    This is a read-model calculation, not an ingest-path calculation. Missing
    quality/trend evidence stays missing; available demand weights are
    renormalized instead of treating missing values as zero.
    """
    if period not in {"7d", "30d", "90d"}:
        raise ValueError("unsupported country demand period")
    by_period: dict[str, dict[str, dict[str, Any]]] = {}
    for snapshot_period, snapshot in snapshots.items():
        by_period[snapshot_period] = {str(item.get("country_code") or "").upper(): item for item in (snapshot or {}).get("countries", [])}
    selected = by_period.get(period, {})
    codes = {code for code, item in selected.items() if code and int(item.get("qualified_requests", 0) or 0) > 0}
    traffic_values = [int(selected.get(code, {}).get("qualified_requests", 0) or 0) for code in codes]
    observed_values = sorted(value for value in traffic_values if value > 0)
    result = []
    for code in sorted(codes):
        demand = selected.get(code, {})
        traffic = int(demand.get("qualified_requests", 0) or 0)
        market = market_scores.get(code, {})
        raw_market = market.get("market_score")
        market_score = float(raw_market) if isinstance(raw_market, (int, float)) else None
        evidence_level, confidence = _evidence_level(traffic)
        rank = sum(value <= traffic for value in observed_values) / len(observed_values) * 100 if observed_values else 0.0
        quality = None
        if float(demand.get("identity_coverage", 0) or 0) > 0:
            quality = float(demand.get("quality_score", 0) or 0) * 100
        trend_pct = demand.get("trend_pct")
        momentum = max(0.0, min(100.0, 50.0 + float(trend_pct))) if trend_pct is not None else None
        demand_parts = [(0.25, rank), (0.15, quality), (0.10, momentum)]
        available = [(weight, value) for weight, value in demand_parts if value is not None]
        demand_score = sum(weight * value for weight, value in available) / sum(weight for weight, _ in available) if available else None
        country_demand_score = demand.get("country_demand_score")
        demand_confidence = demand.get("demand_confidence")
        adjusted_demand_score = None
        opportunity_score = None
        if isinstance(country_demand_score, (int, float)):
            adjusted_demand_score = round(50.0 + float(demand_confidence or 0.0) * (float(country_demand_score) - 50.0), 1)
        if market_score is not None and adjusted_demand_score is not None:
            opportunity_score = round(0.60 * market_score + 0.40 * adjusted_demand_score, 1)
        traffic_7d = int(by_period.get("7d", {}).get(code, {}).get("qualified_requests", 0) or 0)
        traffic_90d = int(by_period.get("90d", {}).get(code, {}).get("qualified_requests", 0) or 0)
        recent_share = round(traffic_7d / traffic_90d * 100, 1) if traffic_90d else None
        state = _opportunity_state(traffic, market_score, evidence_level, rank)
        opportunity_status = _opportunity_status(market_score, country_demand_score, demand_confidence, opportunity_score)
        name = market.get("country_name") or demand.get("country_name") or code
        explanation = (f"Market Score {market_score:.1f}; Demand Score {float(country_demand_score):.1f}; Demand Confidence {float(demand_confidence or 0.0):.0%}; Adjusted Demand {adjusted_demand_score:.1f}; Opportunity {opportunity_score:.1f}. "
                       f"Status {opportunity_status}; demand evidence is {'sufficient' if float(demand_confidence or 0.0) >= 0.60 else 'limited'}.") if market_score is not None and adjusted_demand_score is not None else f"{traffic} qualified requests observed in {period}. Market score or demand unavailable."
        if market_score is None:
            explanation = f"{traffic} qualified requests observed in {period}. Market score unavailable."
        result.append({
            "country_code": code, "country_name": name, "market_score": market_score,
            "opportunity_score": opportunity_score, "opportunity_state": state,
            "country_demand_score": country_demand_score, "demand_confidence": demand_confidence,
            "weighted_qualified_sessions": demand.get("weighted_qualified_sessions"),
            "evidence_coverage": demand.get("evidence_coverage"),
            "adjusted_demand_score": adjusted_demand_score, "opportunity_status": opportunity_status,
            "opportunity_reason": explanation,
            "traffic_7d": traffic_7d, "traffic_30d": traffic, "traffic_90d": traffic_90d,
            "recent_traffic_share_pct": recent_share,
            "trend_pct": round(float(trend_pct), 2) if trend_pct is not None else None,
            "evidence_level": evidence_level, "evidence_confidence": confidence,
            "traffic_strength": round(rank, 1), "quality_score": round(quality, 1) if quality is not None else None,
            "explanation": explanation,
        })
    result.sort(key=lambda item: (-(item["opportunity_score"] if item["opportunity_score"] is not None else -1), item["country_name"]))
    return {"period": period, "countries": result}


__all__ = ["CountryDemandConfig", "aggregate_country_demand", "build_country_opportunities", "exclusion_state"]
