"""Data completeness signals used to explain confidence without changing labels."""

from __future__ import annotations


def data_health(observation: dict | None, profile: dict | None, ai_profile: dict | None, cluster: dict | None) -> dict:
    observation, profile, ai_profile = observation or {}, profile or {}, ai_profile or {}
    bucket_history = observation.get("bucket_history_hours")
    rule_coverage = bool(observation.get("rule_coverage", bucket_history is not None and float(bucket_history or 0) >= 24))
    ai_confidence = int(ai_profile.get("confidence") or 0) if ai_profile else 0
    health = {
        "core_enrichment_status": profile.get("core_enrichment_status") or profile.get("enrichment_status") or "unknown",
        "privacy_enrichment_status": profile.get("privacy_enrichment_status") or "unknown",
        "ai_confidence": ai_confidence,
        "ai_confidence_level": ai_profile.get("confidence_level") if ai_profile else "unavailable",
        "rule_coverage": rule_coverage,
        "cluster_available": bool(cluster),
    }
    health["complete"] = (health["core_enrichment_status"] == "complete" and health["privacy_enrichment_status"] == "complete" and rule_coverage and bool(ai_profile))
    return health


def confidence_for_label(label: str, health: dict) -> tuple[int, list[str]]:
    base = {"bad": 90, "watch": 75, "good": 65, "unknown": 35}.get(label, 35)
    score, factors = base, [f"base label confidence {base}"]
    if health.get("core_enrichment_status") == "complete":
        score += 5; factors.append("core enrichment complete (+5)")
    if health.get("privacy_enrichment_status") == "complete":
        score += 5; factors.append("privacy enrichment complete (+5)")
    if health.get("ai_confidence_level") == "high":
        score += 8; factors.append("AI confidence high (+8)")
    elif health.get("ai_confidence_level") == "medium":
        score += 4; factors.append("AI confidence medium (+4)")
    if health.get("rule_coverage"):
        score += 5; factors.append("rule history covered (+5)")
    if health.get("cluster_available"):
        score += 2; factors.append("network correlation available (+2)")
    return max(0, min(100, score)), factors
