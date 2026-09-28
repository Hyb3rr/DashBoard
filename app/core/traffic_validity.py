"""Normalized traffic-validity evidence; policy/scoring is intentionally separate."""

from __future__ import annotations

from typing import Any


def optional_bool(value: Any) -> bool | None:
    """Normalize ClickHouse UInt8/Python boolean values without collapsing unknown."""
    if value is None:
        return None
    if value is True or value == 1:
        return True
    if value is False or value == 0:
        return False
    if isinstance(value, str) and value.strip() in {"0", "1"}:
        return value.strip() == "1"
    raise ValueError(f"invalid boolean-like value: {value!r}")


def _optional_bool(event: dict[str, Any], key: str) -> bool | None:
    """Normalize one optional traffic validity flag from an event."""
    return optional_bool(event.get(key))


def normalize_traffic_evidence(event: dict[str, Any]) -> dict[str, Any]:
    """Return stable evidence namespaces without interpreting missing data as clean."""
    return {
        "bot_evidence": {
            "cf_bot_score": event.get("cf_bot_score"),
            "known_bot": event.get("known_bot") if event.get("known_bot") is not None else event.get("bot_detected"),
            "scanner": event.get("is_scanner") if event.get("is_scanner") is not None else event.get("scanner_detected"),
        },
        "browser_evidence": {
            "js_detection_passed": _optional_bool(event, "cf_js_detection_passed"),
        },
        "network_evidence": {
            "tor": _optional_bool(event, "is_tor"),
            "vpn": _optional_bool(event, "is_vpn"),
            "proxy": _optional_bool(event, "is_proxy"),
            "hosting": _optional_bool(event, "is_hosting"),
            "mobile": _optional_bool(event, "is_mobile"),
        },
        "geo_evidence": {
            "assigned_country": event.get("country_code"),
            "geo_confidence": event.get("geo_confidence"),
            "geo_conflict": _optional_bool(event, "geo_conflict"),
        },
        "engagement_evidence": {
            "engagement_seconds": event.get("engagement_seconds"),
            "pageviews": event.get("pageviews"),
            "key_event_count": event.get("key_event_count"),
        },
    }


def evaluate_traffic_validity(event: dict[str, Any]) -> dict[str, Any]:
    """Apply the V1 deterministic validity policy to one normalized observation."""
    evidence = normalize_traffic_evidence(event)
    bot = evidence["bot_evidence"]
    browser = evidence["browser_evidence"]
    network = evidence["network_evidence"]
    reasons: list[str] = []

    if bot["known_bot"] is True:
        return {"traffic_validity_score": 0.0, "traffic_status": "excluded", "validity_confidence": 1.0, "validity_reasons": ["known_bot"]}
    if bot["scanner"] is True:
        return {"traffic_validity_score": 0.0, "traffic_status": "excluded", "validity_confidence": 1.0, "validity_reasons": ["known_scanner"]}
    if network["tor"] is True:
        return {"traffic_validity_score": 0.0, "traffic_status": "excluded", "validity_confidence": 1.0, "validity_reasons": ["tor_exit"]}

    score = 0.50
    observed = 0
    bot_score = bot["cf_bot_score"]
    if bot_score is not None:
        observed += 1
        if int(bot_score) >= 30:
            score += 0.25
            reasons.append("cf_bot_score_likely_human")
        else:
            score -= 0.25
            reasons.append("cf_bot_score_likely_automated")
    if browser["js_detection_passed"] is not None:
        observed += 1
        if browser["js_detection_passed"]:
            score += 0.15
            reasons.append("js_detection_passed")
        else:
            score -= 0.15
            reasons.append("js_detection_failed")
    for key, label, penalty in (("vpn", "vpn", 0.10), ("proxy", "proxy", 0.15), ("hosting", "hosting", 0.15)):
        if network[key] is not None:
            observed += 1
            if network[key]:
                score -= penalty
                reasons.append(f"{label}_network")
    if not reasons and observed == 0:
        return {"traffic_validity_score": None, "traffic_status": "unknown", "validity_confidence": 0.0, "validity_reasons": ["insufficient_validity_evidence"]}
    score = round(max(0.0, min(1.0, score)), 4)
    status = "qualified" if score >= 0.70 else "suspect" if score >= 0.40 else "excluded"
    confidence = round(min(1.0, observed / 3.0), 4)
    if network["mobile"] is True:
        reasons.append("mobile_network_neutral")
    return {"traffic_validity_score": score, "traffic_status": status, "validity_confidence": confidence, "validity_reasons": reasons}


__all__ = ["optional_bool", "normalize_traffic_evidence", "evaluate_traffic_validity"]
