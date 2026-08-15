from __future__ import annotations

from .telemetry import confidence_for_label, data_health


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


def classify_ip(profile: dict, observation: dict | None = None, region_profile: dict | None = None, ai_profile: dict | None = None, cluster: dict | None = None) -> dict:
    """Classify an IP with behavior-first, auditable rule groups.

    A (behavior) is sourced from the normalized observation's behavior_score.
    B (identity) is capped at 25. C is a trust bonus. D is a small
    behavior-gated region nudge. Aggregated risk_score fields are deliberately
    excluded to prevent double-counting.
    """
    observation = observation or {}
    region_profile = region_profile or {}
    evidence: list[str] = []
    behavior_score = max(0, min(int(observation.get("recent_behavior_score", observation.get("behavior_score")) or 0), 100))
    requests = int(observation.get("recent_requests", observation.get("requests")) or 0)
    hard_behavior = int(observation.get("recent_sensitive_probe_requests", observation.get("sensitive_probe_requests")) or 0) > 0

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
        windows_seen = int(ai_profile.get("windows_seen") or 0)
        if group_a < 25 and ai_score >= 70 and windows_seen >= 3:
            group_e = 8
            windows = ai_profile.get("anomalous_windows", 0)
            evidence.append(f"E — AI flagged {windows} anomalous window(s) despite low rule-based score (+8)")

    group_f = 0
    if cluster and len(cluster.get("member_ips") or []) >= 3:
        group_f = min(5, int(cluster.get("campaign_score") or 0) // 20)
        evidence.append(f"F — possible ASN campaign {cluster.get('cluster_id')} ({len(cluster.get('member_ips') or [])} IPs, {len(cluster.get('shared_paths') or [])} shared sensitive paths; +{group_f})")

    base_score = group_a + group_b + group_c + group_d + group_f
    score = max(0, min(base_score + group_e, 100))
    score_explanations = {
        "A": (
            f"A = {group_a}: recent behavior score from request patterns, probes, bots and response errors."
            if group_a else
            "A = 0: no behavior points from the current observation window."
        ),
        "B": (
            f"B = {group_b}: raw identity contribution was {raw_identity}, capped at +25."
            if raw_identity > group_b else
            f"B = {group_b}: privacy or hosting identity signals contributed to the score."
            if group_b else
            "B = 0: no Tor, proxy, VPN or hosting signal was active."
        ),
        "C": "",
        "D": "",
        "E": "",
        "F": "",
    }
    if group_c == -20:
        score_explanations["C"] = f"C = -20: {profile.get('organization')} has confidence {org_confidence}%, is not hosting, and behavior A={group_a} is below 25."
    elif not profile.get("organization"):
        score_explanations["C"] = "C = 0: no attributed organization, so trusted-network reduction cannot activate."
    elif org_confidence < 70:
        score_explanations["C"] = f"C = 0: organization confidence is {org_confidence}%, below required 70%."
    elif profile.get("is_hosting"):
        score_explanations["C"] = "C = 0: hosting/datacenter identity is not eligible for trusted-network reduction."
    else:
        score_explanations["C"] = f"C = 0: trusted-network reduction is disabled because behavior A={group_a} is 25 or higher. High behavior overrides organization trust."

    if group_a == 0:
        score_explanations["D"] = "D = 0: region conflict nudge is behavior-gated and cannot create risk by itself."
    elif group_d:
        score_explanations["D"] = f"D = +{group_d}: behavior exists and region conflict context activated the nudge."
    else:
        score_explanations["D"] = "D = 0: no qualifying medium or high conflict indicator was active."

    if not ai_profile:
        score_explanations["E"] = "E = 0: no local AI score snapshot is available."
    elif group_a >= 25:
        score_explanations["E"] = f"E = 0: AI bonus requires A below 25; current behavior A={group_a}."
    elif ai_score < 70:
        score_explanations["E"] = f"E = 0: AI anomaly score is {ai_score}, below required 70."
    elif windows_seen < 3:
        score_explanations["E"] = f"E = 0: only {windows_seen} AI window(s) observed; minimum is 3."
    else:
        score_explanations["E"] = f"E = +8: AI anomaly score {ai_score} and {windows_seen} windows satisfied the gate."

    if not cluster:
        score_explanations["F"] = "F = 0: no ASN campaign correlation is available."
    elif len(cluster.get("member_ips") or []) < 3:
        score_explanations["F"] = f"F = 0: correlation has {len(cluster.get('member_ips') or [])} member IP(s); minimum is 3."
    elif group_f == 0:
        score_explanations["F"] = "F = 0: campaign exists, but campaign score is below the first +1 threshold."
    else:
        score_explanations["F"] = f"F = +{group_f}: ASN campaign correlation passed the member and campaign-score gates."

    if score != base_score + group_e:
        score_explanations["final"] = f"Final score clamped from {base_score + group_e} into 0–100."
    else:
        score_explanations["final"] = "Final score is the sum of A+B+C+D+E+F with no clamp applied."
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
    health = data_health(observation, profile, ai_profile, cluster)
    confidence, confidence_factors = confidence_for_label(label, health)
    return {
        "label": label,
        "score": score,
        "confidence": confidence,
        "summary": summaries[label],
        "evidence": evidence,
        "score_breakdown": {"behavior_a": group_a, "identity_b": group_b, "trust_c": group_c, "region_d": group_d, "ai_e": group_e, "correlation_f": group_f},
        "score_explanations": score_explanations,
        "data_health": health,
        "confidence_factors": confidence_factors,
    }
