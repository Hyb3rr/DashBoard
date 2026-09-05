"""Data completeness signals used to explain confidence without changing labels."""

from __future__ import annotations


def _normalize_bool(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized == "true":
            return True
        if normalized == "false":
            return False
    return None


def _normalize_confidence(value: object) -> int:
    if isinstance(value, bool):
        return 0
    try:
        numeric = int(value or 0)
    except (TypeError, ValueError, OverflowError):
        return 0
    return max(0, min(100, numeric))


def _normalize_confidence_level(value: object) -> str:
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"low", "medium", "high"}:
            return normalized
    return "unavailable"


def data_health(observation: dict | None, profile: dict | None, ai_profile: dict | None) -> dict:
    observation, profile, ai_profile = observation or {}, profile or {}, ai_profile or {}
    bucket_history = observation.get("bucket_history_hours")
    if "rule_coverage" in observation:
        rule_coverage = _normalize_bool(observation["rule_coverage"]) is True
    else:
        try:
            rule_coverage = bucket_history is not None and float(bucket_history or 0) >= 24
        except (TypeError, ValueError, OverflowError):
            rule_coverage = False
    ai_confidence = _normalize_confidence(ai_profile.get("confidence")) if ai_profile else 0
    ai_confidence_level = _normalize_confidence_level(ai_profile.get("confidence_level")) if ai_profile else "unavailable"
    ai_available = ai_confidence_level != "unavailable"
    health = {
        "core_enrichment_status": profile.get("core_enrichment_status") or profile.get("enrichment_status") or "unknown",
        "privacy_enrichment_status": profile.get("privacy_enrichment_status") or "unknown",
        "ai_confidence": ai_confidence,
        "ai_confidence_level": ai_confidence_level,
        "rule_coverage": rule_coverage,
    }
    health["complete"] = (health["core_enrichment_status"] == "complete" and health["privacy_enrichment_status"] == "complete" and rule_coverage and ai_available)
    return health


def confidence_for_label(label: str, health: dict) -> tuple[int, list[str]]:
    base = {"critical": 90, "medium": 75, "low": 70, "good": 65, "unknown": 35}.get(label, 35)
    score, factors = base, [f"base label confidence {base}"]
    if health.get("core_enrichment_status") == "complete":
        score += 5
        factors.append("core enrichment complete (+5)")
    if health.get("privacy_enrichment_status") == "complete":
        score += 5
        factors.append("privacy enrichment complete (+5)")
    if health.get("ai_confidence_level") == "high":
        score += 8
        factors.append("AI confidence high (+8)")
    elif health.get("ai_confidence_level") == "medium":
        score += 4
        factors.append("AI confidence medium (+4)")
    if health.get("rule_coverage"):
        score += 5
        factors.append("rule history covered (+5)")
    return max(0, min(100, score)), factors
