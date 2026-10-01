"""Classification orchestration and process-local scoring comparison metrics."""

from collections.abc import Mapping
from collections.abc import Callable
from typing import Any

from ..core import metrics
from ..core.intelligence import _classification_label, classify_ip
from ..core.shadow_scoring import family_max_behavior_score


def _behavior_score(observation: Mapping[str, Any]) -> int:
    """Read the same recent-versus-legacy behavior score selected by V1."""
    key = "recent_behavior_score" if "recent_behavior_score" in observation else "behavior_score"
    try:
        return max(0, min(int(observation.get(key) or 0), 100))
    except (TypeError, ValueError, OverflowError):
        return 0


def _record_shadow_comparison(v1_score: int, family_score: int) -> None:
    """Record bounded aggregate counters without IP labels or per-IP logs."""
    delta = family_score - v1_score
    metrics.increment("scoring.family_max.observations")
    metrics.increment("scoring.family_max.v1_behavior_points", v1_score)
    metrics.increment("scoring.family_max.shadow_behavior_points", family_score)
    if delta > 0:
        metrics.increment("scoring.family_max.delta_positive_samples")
        metrics.increment("scoring.family_max.delta_positive_points", delta)
    elif delta < 0:
        metrics.increment("scoring.family_max.delta_negative_samples")
        metrics.increment("scoring.family_max.delta_negative_points", -delta)
    else:
        metrics.increment("scoring.family_max.delta_zero_samples")
    metrics.gauge("scoring.family_max.last_v1_behavior_score", v1_score)
    metrics.gauge("scoring.family_max.last_shadow_behavior_score", family_score)
    metrics.gauge("scoring.family_max.last_delta", delta)


def classify_with_rollout_metrics(
    profile: dict,
    observation: dict | None = None,
    region_profile: dict | None = None,
    ai_profile: dict | None = None,
    *,
    classifier: Callable[..., dict] | None = None,
) -> dict:
    """Classify with V1 and measure family-max from the selected recent detections."""
    observation = observation or {}
    classification = (classifier or classify_ip)(profile, observation, region_profile, ai_profile)
    v1_score = _behavior_score(observation)
    detections = observation.get("detections_recent")
    if isinstance(detections, list):
        family_score = family_max_behavior_score(detections)
        _record_shadow_comparison(v1_score, family_score)
    else:
        family_score = None
        metrics.increment("scoring.family_max.missing_recent_detections")
    active_mode = "family_max" if family_score is not None else "v1"
    effective_score = family_score if active_mode == "family_max" else v1_score
    # Keep the observed V1 score intact; persist the active A input separately so
    # provenance can reproduce the exact scoring mode without a schema change.
    observation["classification_scoring_mode"] = active_mode
    observation["classification_behavior_score"] = effective_score
    if active_mode == "family_max":
        classification = _apply_family_max_behavior(classification, observation, family_score)
        metrics.increment("scoring.family_max.mode_family_max_samples")
    else:
        metrics.increment("scoring.family_max.mode_v1_samples")
        metrics.increment("scoring.family_max.mode_fallback_missing_detections")
    return classification


def _apply_family_max_behavior(
    v1_classification: dict,
    observation: Mapping[str, Any],
    family_score: int,
) -> dict:
    """Replace only behavior A while retaining V1 supporting groups and confidence."""
    breakdown = v1_classification["score_breakdown"]
    identity = int(breakdown["identity_b"])
    trust = int(breakdown["trust_c"])
    region = int(breakdown["region_d"])
    ai_bonus = int(breakdown["ai_e"])
    requests = int(observation.get("recent_requests", observation.get("requests")) or 0)
    sensitive_key = (
        "recent_sensitive_probe_requests"
        if "recent_sensitive_probe_requests" in observation
        else "sensitive_probe_requests"
    )
    hard_sensitive = int(observation.get(sensitive_key) or 0) > 0
    base_score = family_score + identity + trust + region
    score = max(0, min(base_score + ai_bonus, 100))
    label = _classification_label(
        requests, family_score, identity, ai_bonus, hard_sensitive, base_score, score
    )

    result = dict(v1_classification)
    result["label"] = label
    result["score"] = score
    result["summary"] = {
        "critical": "High likelihood of hostile behavior or unwanted network activity",
        "medium": "Needs review before being treated as benign",
        "low": "Weak signal; monitor for additional evidence",
        "good": "No strong hostile indicators in current evidence",
        "unknown": "Insufficient traffic or identity evidence to classify",
    }[label]
    result["score_breakdown"] = {**breakdown, "behavior_a": family_score}
    explanations = dict(v1_classification.get("score_explanations") or {})
    explanations["A"] = (
        f"A = {family_score}: family-max of the selected recent rule detections; "
        f"V1 behavior score was {breakdown['behavior_a']}."
    )
    explanations["final"] = (
        f"Final score clamped from {base_score + ai_bonus} into 0–100."
        if score != base_score + ai_bonus
        else "Final score is the sum of A+B+C+D+E with no clamp applied."
    )
    result["score_explanations"] = explanations
    # Confidence intentionally stays identical to V1 during this rollout.
    return result
