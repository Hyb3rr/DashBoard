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
            candidate, candidate_evidence = 5, "Region conflict severity high (+5)"
        elif severity_level == "medium" or "elevated geopolitical conflict" in value or item_type == "elevated_tension":
            candidate, candidate_evidence = 3, "Region conflict severity medium (+3)"
        else:
            continue
        if candidate > severity:
            severity, evidence = candidate, candidate_evidence
    return min(severity, 5), evidence


def _behavior_signal(observation: dict) -> tuple[int, int, bool, list[str]]:
    """Read the authoritative behavior score, traffic volume, and evidence."""
    recent_window = "recent_behavior_score" in observation
    behavior_score = max(0, min(int(
        observation.get("recent_behavior_score" if recent_window else "behavior_score") or 0
    ), 100))
    requests = int(observation.get("recent_requests", observation.get("requests")) or 0)
    hard_behavior = int(observation.get("recent_sensitive_probe_requests", observation.get("sensitive_probe_requests")) or 0) > 0
    behavior_evidence = observation.get(
        "recent_behavior_evidence" if recent_window else "behavior_evidence"
    ) or []
    evidence = [f"A — {item}" for item in behavior_evidence]
    if not evidence and behavior_score:
        evidence.append(f"A — behavior score {behavior_score}/100")
    return behavior_score, requests, hard_behavior, evidence


def _identity_signal(profile: dict) -> tuple[int, int, list[str]]:
    """Calculate capped supporting points and evidence for network identity."""
    identity_points = (
        (15 if profile.get("is_tor") else 0, "Tor exit signal"),
        (10 if profile.get("is_proxy") else 0, "Proxy signal"),
        (8 if profile.get("is_vpn") else 0, "VPN signal"),
        (5 if profile.get("is_hosting") else 0, "Hosting/datacenter signal"),
    )
    raw_identity = sum(points for points, _ in identity_points)
    group_b = min(raw_identity, 25)
    evidence = [f"B — {label} (+{points})" for points, label in identity_points if points]
    if raw_identity > group_b:
        evidence.append("B — identity contribution capped at +25")
    return group_b, raw_identity, evidence


def _trust_signal(profile: dict, behavior_score: int) -> tuple[int, int, list[str]]:
    """Apply the low-behavior trusted-organization reduction when eligible."""
    confidence = int(profile.get("organization_confidence") or 0)
    eligible = (
        profile.get("organization")
        and confidence >= 70
        and not profile.get("is_hosting")
        and behavior_score < 25
    )
    evidence = ["C — stable attributed network with low behavior risk (-20)"] if eligible else []
    return (-20 if eligible else 0), confidence, evidence


def _region_signal(profile: dict, region_profile: dict, behavior_score: int) -> tuple[int, list[str]]:
    """Apply conflict context only when behavior evidence already exists."""
    points, evidence = _region_nudge(region_profile) if behavior_score > 0 else (0, None)
    result = [f"D — {evidence}"] if evidence else []
    if profile.get("country_code") and region_profile.get("country_name"):
        result.append(f"Region profile available for {region_profile['country_name']}")
    return points, result


def _ai_signal(ai_profile: dict | None, behavior_score: int) -> tuple[int, int, int, list[str]]:
    """Apply the gated local anomaly bonus and return its observed inputs."""
    if not ai_profile:
        return 0, 0, 0, []
    ai_score = int(ai_profile.get("ai_anomaly_score") or 0)
    windows_seen = int(ai_profile.get("windows_seen") or 0)
    if behavior_score < 25 and ai_score >= 70 and windows_seen >= 3:
        windows = ai_profile.get("anomalous_windows", 0)
        evidence = [f"E — AI flagged {windows} anomalous window(s) despite low rule-based score (+8)"]
        return 8, ai_score, windows_seen, evidence
    return 0, ai_score, windows_seen, []


def _score_explanations(profile, ai_profile, behavior, identity, trust, region, ai, score, base_score):
    """Explain every score group and any final score clamp in plain language."""
    group_a, group_b, group_c, group_d, group_e = behavior, identity[0], trust[0], region[0], ai[0]
    raw_identity, org_confidence = identity[1], trust[1]
    ai_score, windows_seen = ai[1], ai[2]
    explanations = {
        "A": (
            f"A = {group_a}: recent behavior score from request patterns, probes, bots and response errors."
            if group_a else "A = 0: no behavior points from the current observation window."
        ),
        "B": (
            f"B = {group_b}: raw identity contribution was {raw_identity}, capped at +25."
            if raw_identity > group_b else
            f"B = {group_b}: privacy or hosting identity signals contributed to the score."
            if group_b else "B = 0: no Tor, proxy, VPN or hosting signal was active."
        ),
        "C": "",
        "D": "",
        "E": "",
    }
    if group_c == -20:
        explanations["C"] = f"C = -20: {profile.get('organization')} has confidence {org_confidence}%, is not hosting, and behavior A={group_a} is below 25."
    elif not profile.get("organization"):
        explanations["C"] = "C = 0: no attributed organization, so trusted-network reduction cannot activate."
    elif org_confidence < 70:
        explanations["C"] = f"C = 0: organization confidence is {org_confidence}%, below required 70%."
    elif profile.get("is_hosting"):
        explanations["C"] = "C = 0: hosting/datacenter identity is not eligible for trusted-network reduction."
    else:
        explanations["C"] = f"C = 0: trusted-network reduction is disabled because behavior A={group_a} is 25 or higher. High behavior overrides organization trust."

    if group_a == 0:
        explanations["D"] = "D = 0: region conflict nudge is behavior-gated and cannot create risk by itself."
    elif group_d:
        explanations["D"] = f"D = +{group_d}: behavior exists and region conflict context activated the nudge."
    else:
        explanations["D"] = "D = 0: no qualifying medium or high conflict indicator was active."

    if not ai_profile:
        explanations["E"] = "E = 0: no local AI score snapshot is available."
    elif group_a >= 25:
        explanations["E"] = f"E = 0: AI bonus requires A below 25; current behavior A={group_a}."
    elif ai_score < 70:
        explanations["E"] = f"E = 0: AI anomaly score is {ai_score}, below required 70."
    elif windows_seen < 3:
        explanations["E"] = f"E = 0: only {windows_seen} AI window(s) observed; minimum is 3."
    else:
        explanations["E"] = f"E = +8: AI anomaly score {ai_score} and {windows_seen} windows satisfied the gate."
    explanations["final"] = (
        f"Final score clamped from {base_score + group_e} into 0–100."
        if score != base_score + group_e
        else "Final score is the sum of A+B+C+D+E with no clamp applied."
    )
    return explanations


def _classification_label(requests, behavior, identity, ai_bonus, hard_behavior, base_score, score):
    """Choose a verdict from the established evidence and score thresholds."""
    if requests < 3 and behavior == 0 and identity == 0 and ai_bonus == 0:
        return "unknown"
    if hard_behavior or base_score >= 60:
        return "critical"
    if score >= 30 or ai_bonus > 0:
        return "medium"
    if score >= 10:
        return "low"
    return "good"


def classify_ip(profile: dict, observation: dict | None = None, region_profile: dict | None = None, ai_profile: dict | None = None) -> dict:
    """Classify an IP with behavior-first, auditable rule groups."""
    observation, region_profile = observation or {}, region_profile or {}
    behavior, requests, hard_behavior, evidence = _behavior_signal(observation)
    identity, raw_identity, identity_evidence = _identity_signal(profile)
    trust, org_confidence, trust_evidence = _trust_signal(profile, behavior)
    region, region_evidence = _region_signal(profile, region_profile, behavior)
    ai_bonus, ai_score, windows_seen, ai_evidence = _ai_signal(ai_profile, behavior)
    evidence.extend(identity_evidence)
    evidence.extend(trust_evidence)
    evidence.extend(region_evidence)
    evidence.extend(ai_evidence)

    base_score = behavior + identity + trust + region
    score = max(0, min(base_score + ai_bonus, 100))
    label = _classification_label(
        requests, behavior, identity, ai_bonus, hard_behavior, base_score, score
    )
    explanations = _score_explanations(
        profile,
        ai_profile,
        behavior,
        (identity, raw_identity),
        (trust, org_confidence),
        (region,),
        (ai_bonus, ai_score, windows_seen),
        score,
        base_score,
    )
    summaries = {
        "critical": "High likelihood of hostile behavior or unwanted network activity",
        "medium": "Needs review before being treated as benign",
        "low": "Weak signal; monitor for additional evidence",
        "good": "No strong hostile indicators in current evidence",
        "unknown": "Insufficient traffic or identity evidence to classify",
    }
    health = data_health(observation, profile, ai_profile)
    confidence, confidence_factors = confidence_for_label(label, health)
    return {
        "label": label,
        "score": score,
        "confidence": confidence,
        "summary": summaries[label],
        "evidence": evidence,
        "score_breakdown": {
            "behavior_a": behavior,
            "identity_b": identity,
            "trust_c": trust,
            "region_d": region,
            "ai_e": ai_bonus,
        },
        "score_explanations": explanations,
        "data_health": health,
        "confidence_factors": confidence_factors,
    }
