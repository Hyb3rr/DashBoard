from __future__ import annotations


def _region_nudge(region_profile: dict) -> tuple[int, str | None]:
    """Return a small, behavior-gated conflict nudge from typed indicators."""
    indicators = region_profile.get("conflict_indicators") or []
    severity = 0
    evidence = None
    for item in indicators:
        if not isinstance(item, dict):
            continue
        value = str(item.get("value", "")).lower()
        item_type = str(item.get("type", "")).lower()
        severity_level = str(item.get("severity") or "").lower()
        if item_type in {"interstate_war", "civil_war"} or severity_level in {"high", "critical"} or "active interstate war" in value or "active civil war" in value:
            severity = max(severity, 5)
            evidence = "Region conflict severity high (+5)"
        elif severity_level == "medium" or "elevated geopolitical conflict" in value or item_type == "elevated_tension":
            severity = max(severity, 3)
            evidence = "Region conflict severity medium (+3)"
    return min(severity, 5), evidence


def classify_ip(profile: dict, observation: dict | None = None, region_profile: dict | None = None, ai_profile: dict | None = None) -> dict:
    """Classify an IP with behavior-first, auditable rule groups.

    A (behavior) is sourced from the normalized observation's behavior_score.
    B (identity) is capped at 25. C is a trust bonus. D is a small
    behavior-gated region nudge. Aggregated risk_score fields are deliberately
    excluded to prevent double-counting.
    """
    observation = observation or {}
    region_profile = region_profile or {}
    evidence: list[str] = []
    behavior_score = max(0, min(int(observation.get("behavior_score") or 0), 100))
    requests = int(observation.get("requests") or 0)
    hard_behavior = int(observation.get("sensitive_probe_requests") or 0) > 0

    # Group A: logs.py is the single owner of behavior scoring.
    group_a = behavior_score
    behavior_evidence = observation.get("behavior_evidence") or []
    if behavior_evidence:
        evidence.extend(f"A — {item}" for item in behavior_evidence)
    elif group_a:
        evidence.append(f"A — behavior score {group_a}/100")

    # Group B: network identity is a supporting signal only.
    identity_points = (
        (15 if profile.get("is_tor") else 0, "Tor exit signal"),
        (10 if profile.get("is_proxy") else 0, "Proxy signal"),
        (8 if profile.get("is_vpn") else 0, "VPN signal"),
        (5 if profile.get("is_hosting") else 0, "Hosting/datacenter signal"),
    )
    raw_identity = sum(points for points, _ in identity_points)
    group_b = min(raw_identity, 25)
    for points, label in identity_points:
        if points:
            evidence.append(f"B — {label} (+{points})")
    if raw_identity > group_b:
        evidence.append("B — identity contribution capped at +25")

    # Group C: only a low-behavior, attributable network gets a trust bonus.
    group_c = 0
    org_confidence = int(profile.get("organization_confidence") or 0)
    if profile.get("organization") and org_confidence >= 70 and not profile.get("is_hosting") and group_a < 25:
        group_c = -20
        evidence.append("C — stable attributed network with low behavior risk (-20)")

    # Group D: region never creates risk for a behaviorally clean IP.
    group_d = 0
    if group_a > 0:
        group_d, region_evidence = _region_nudge(region_profile)
        if region_evidence:
            evidence.append(f"D — {region_evidence}")
    if profile.get("country_code") and region_profile.get("country_name"):
        evidence.append(f"Region profile available for {region_profile['country_name']}")

    group_e = 0
    if ai_profile:
        ai_score = int(ai_profile.get("ai_anomaly_score") or 0)
        if group_a < 25 and ai_score >= 70:
            group_e = 8
            windows = ai_profile.get("anomalous_windows", 0)
            evidence.append(f"E — AI flagged {windows} anomalous window(s) despite low rule-based score (+8)")

    base_score = group_a + group_b + group_c + group_d
    score = max(0, min(base_score + group_e, 100))
    if requests < 3 and group_a == 0 and group_b == 0 and group_e == 0:
        label = "unknown"
    elif hard_behavior or base_score >= 60:
        label = "bad"
    elif score >= 30 or group_e > 0:
        label = "watch"
    else:
        label = "good"

    summaries = {
        "bad": "High likelihood of hostile behavior or unwanted network activity",
        "watch": "Needs review before being treated as benign",
        "good": "No strong hostile indicators in current evidence",
        "unknown": "Insufficient traffic or identity evidence to classify",
    }
    confidence = 90 if label == "bad" else 75 if label == "watch" else 65 if label == "good" else 35
    return {
        "label": label,
        "score": score,
        "confidence": confidence,
        "summary": summaries[label],
        "evidence": evidence,
        "score_breakdown": {"behavior_a": group_a, "identity_b": group_b, "trust_c": group_c, "region_d": group_d, "ai_e": group_e},
    }
