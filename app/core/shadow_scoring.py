"""Pure family aggregation used by shadow measurement and scoring rollout."""

from __future__ import annotations

from collections.abc import Iterable, Mapping


FAMILY_MAP = {
    "WEB-RATE-001": "traffic_rate",
    "WEB-BURST-001": "traffic_rate",
    "WEB-4XX-001": "http_error_activity",
    "WEB-BOT-001": "http_error_activity",
    "WEB-SCAN-001": "reconnaissance",
    "WEB-SENSITIVE-001": "reconnaissance",
    "WEB-BRUTE-001": "credential_attack",
    "firehol:abuseipdb_1d": "abuse_reputation",
    "firehol:abuseipdb_30d": "abuse_reputation",
}

FAMILY_RULES = {
    "traffic_rate": ("WEB-RATE-001", "WEB-BURST-001"),
    "http_error_activity": ("WEB-4XX-001", "WEB-BOT-001"),
    "reconnaissance": ("WEB-SCAN-001", "WEB-SENSITIVE-001"),
    "credential_attack": ("WEB-BRUTE-001",),
    "abuse_reputation": ("firehol:abuseipdb_1d", "firehol:abuseipdb_30d"),
}


def family_max_behavior_score(detections: Iterable[Mapping]) -> int:
    """Aggregate recent rule points by family, preserving unknown rules additively.

    Production detections use ``id`` and ``points``; the offline scorer uses
    ``observed.rule_id`` and ``score_contribution``. Unknown rule IDs remain
    independent families so adding a rule cannot silently remove its points.
    """
    family_scores: dict[str, int] = {}
    for detection in detections:
        if not isinstance(detection, Mapping):
            continue
        rule_id = detection.get("id") or detection.get("rule_id")
        if not isinstance(rule_id, str) or not rule_id:
            continue
        points = detection.get("points", detection.get("score_contribution"))
        if isinstance(points, bool) or not isinstance(points, int) or points < 0:
            continue
        family = FAMILY_MAP.get(rule_id, f"unmapped:{rule_id}")
        family_scores[family] = max(family_scores.get(family, 0), points)
    return min(sum(family_scores.values()), 100)

# These associations are documented for review, but are not mechanically
# discounted: the current rules do not prove that the underlying events overlap.
POSSIBLE_CROSS_FAMILY_CORRELATIONS = (
    ("credential_attack", "traffic_rate"),
    ("credential_attack", "http_error_activity"),
)


def _evidence_key(item: Mapping) -> str | None:
    """Return the rule or provider identifier used by the static family map."""
    observed = item.get("observed")
    rule_id = item.get("rule_id") or (observed.get("rule_id") if isinstance(observed, Mapping) else None)
    if rule_id:
        return str(rule_id)
    source = item.get("source")
    if source:
        return str(source).lower()
    return None


def score_shadow(
    evidence: Iterable[Mapping],
    *,
    available_families: Iterable[str] = (),
) -> dict:
    """Score evidence without changing or calling production classification.

    Each evidence item needs an integer ``score_contribution``. Correlated
    members within a family use their maximum contribution; family scores are
    then summed and clamped to 0–100. ``available_families`` lets callers
    distinguish an observed zero from a source whose evidence was unavailable.
    """
    rows = []
    by_family: dict[str, list[dict]] = {family: [] for family in FAMILY_RULES}
    unmapped = []

    for item in evidence:
        if not isinstance(item, Mapping):
            raise TypeError("each evidence item must be a mapping")
        key = _evidence_key(item)
        family = FAMILY_MAP.get(key) if key else None
        contribution = item.get("score_contribution")
        if isinstance(contribution, bool) or not isinstance(contribution, int):
            raise ValueError("evidence score_contribution must be an integer")
        if contribution < 0:
            raise ValueError("shadow risk contributions must be non-negative")

        row = {**dict(item), "family": family}
        rows.append(row)
        if family is None:
            unmapped.append(row)
        else:
            by_family[family].append(row)

    family_scores = {}
    correlation_adjustments = []
    for family, members in by_family.items():
        raw_total = sum(item["score_contribution"] for item in members)
        family_score = max((item["score_contribution"] for item in members), default=0)
        family_scores[family] = family_score
        removed = raw_total - family_score
        if removed > 0:
            correlation_adjustments.append({
                "family": family,
                "method": "maximum_within_correlated_family",
                "raw_total": raw_total,
                "family_score": family_score,
                "removed_points": removed,
                "evidence_ids": [item.get("evidence_id") or _evidence_key(item) for item in members],
            })

    covered = set(available_families)
    unexpected_families = covered - FAMILY_RULES.keys()
    if unexpected_families:
        raise ValueError(f"unknown evidence families: {', '.join(sorted(unexpected_families))}")
    covered.update(row["family"] for row in rows if row["family"] is not None)
    missing_evidence = [
        {"family": family, "reason": "source_coverage_not_confirmed"}
        for family in FAMILY_RULES if family not in covered
    ]
    raw_sum = sum(family_scores.values())
    final_score = max(0, min(raw_sum, 100))
    if raw_sum != final_score:
        correlation_adjustments.append({
            "family": "all",
            "method": "final_score_clamp",
            "raw_total": raw_sum,
            "family_score": final_score,
            "removed_points": raw_sum - final_score,
            "evidence_ids": [],
        })

    return {
        "family_scores": family_scores,
        "raw_evidence": rows,
        "correlation_adjustments": correlation_adjustments,
        "missing_evidence": missing_evidence,
        "unmapped_evidence": unmapped,
        "possible_cross_family_correlations": [list(pair) for pair in POSSIBLE_CROSS_FAMILY_CORRELATIONS],
        "raw_family_total": raw_sum,
        "final_score": final_score,
        "formula": "clamp(sum(max(score_contribution per evidence family)), 0, 100)",
        "mode": "shadow_only",
    }
