"""Canonical fingerprints for the inputs read by the classifier contract."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from app.core.telemetry import _normalize_bool, _normalize_confidence, _normalize_confidence_level


CLASSIFICATION_INPUT_VERSION = "classification-input-v2"


def _region_inputs(region_profile: Mapping[str, Any]) -> dict[str, Any]:
    """Keep only region fields read by the current classifier."""
    indicators = region_profile.get("conflict_indicators") or []
    return {
        "country_name": region_profile.get("country_name"),
        "conflict_indicators": [
            {
                "type": item.get("type"),
                "severity": item.get("severity"),
                "value": item.get("value"),
            }
            for item in indicators
            if isinstance(item, Mapping)
        ],
    }


def _behavior_inputs(observation: Mapping[str, Any]) -> tuple[dict[str, Any], int]:
    """Project behavior values after the same window selection and normalization."""
    recent_window = "recent_behavior_score" in observation
    score_value = observation.get("recent_behavior_score" if recent_window else "behavior_score") or 0
    behavior_score = max(0, min(int(score_value), 100))
    requests = int(observation.get("recent_requests", observation.get("requests")) or 0)
    sensitive = int(
        observation.get("recent_sensitive_probe_requests", observation.get("sensitive_probe_requests")) or 0
    ) > 0
    evidence_key = "recent_behavior_evidence" if recent_window else "behavior_evidence"
    evidence = observation.get(evidence_key) or []
    rendered_evidence = [f"A — {item}" for item in evidence]
    if not rendered_evidence and behavior_score:
        rendered_evidence.append(f"A — behavior score {behavior_score}/100")
    if "rule_coverage" in observation:
        rule_coverage = _normalize_bool(observation["rule_coverage"]) is True
    else:
        bucket_history = observation.get("bucket_history_hours")
        try:
            rule_coverage = bucket_history is not None and float(bucket_history or 0) >= 24
        except (TypeError, ValueError, OverflowError):
            rule_coverage = False
    mode = observation.get("classification_scoring_mode") or "v1"
    effective_value = observation.get("classification_behavior_score", behavior_score)
    try:
        effective_score = max(0, min(int(effective_value or 0), 100))
    except (TypeError, ValueError, OverflowError):
        effective_score = behavior_score
    projected_detections = None
    if mode == "family_max":
        detections = observation.get("detections_recent")
        if isinstance(detections, list):
            projected_detections = []
            for item in detections:
                if not isinstance(item, Mapping):
                    continue
                rule_id = item.get("id") or item.get("rule_id")
                points = item.get("points", item.get("score_contribution"))
                if (
                    not isinstance(rule_id, str)
                    or not rule_id
                    or isinstance(points, bool)
                    or not isinstance(points, int)
                    or points < 0
                ):
                    continue
                projected_detections.append({"rule_id": rule_id, "points": points})
            projected_detections.sort(key=lambda item: (item["rule_id"], item["points"]))
    inputs = {
        "behavior_score": behavior_score,
        "effective_behavior_score": effective_score,
        "scoring_mode": mode,
        "behavior_window": "recent" if recent_window else "legacy",
        "requests": requests,
        "hard_sensitive_probe": sensitive,
        "evidence": rendered_evidence,
        "rule_coverage": rule_coverage,
    }
    if mode == "family_max":
        inputs["selected_rule_points"] = projected_detections
    return inputs, behavior_score


def canonical_classification_inputs(
    profile: Mapping[str, Any] | None,
    observation: Mapping[str, Any] | None = None,
    region_profile: Mapping[str, Any] | None = None,
    ai_profile: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Project only fields read by scoring, label, evidence, or confidence logic."""
    profile = profile or {}
    observation = observation or {}
    region_profile = region_profile or {}
    ai_profile = ai_profile or {}

    behavior, behavior_score = _behavior_inputs(observation)
    country_code_present = bool(profile.get("country_code"))
    ai_present = bool(ai_profile)
    ai_score = int(ai_profile.get("ai_anomaly_score") or 0) if ai_present else 0
    ai_windows = int(ai_profile.get("windows_seen") or 0) if ai_present else 0
    ai_confidence_level = (
        _normalize_confidence_level(ai_profile.get("confidence_level"))
        if ai_present else "unavailable"
    )
    ai_bonus_eligible = ai_present and behavior_score < 25 and ai_score >= 70 and ai_windows >= 3
    region = _region_inputs(region_profile) if behavior_score > 0 else {
        "country_name": None,
        "conflict_indicators": [],
    }
    if not country_code_present:
        region["country_name"] = None
    organization_confidence = int(profile.get("organization_confidence") or 0)
    core_enrichment_status = profile.get("core_enrichment_status") or profile.get("enrichment_status") or "unknown"
    privacy_enrichment_status = profile.get("privacy_enrichment_status") or "unknown"

    return {
        "profile": {
            "is_tor": bool(profile.get("is_tor")),
            "is_proxy": bool(profile.get("is_proxy")),
            "is_vpn": bool(profile.get("is_vpn")),
            "is_hosting": bool(profile.get("is_hosting")),
            "organization": profile.get("organization") or None,
            "organization_confidence": organization_confidence,
            "country_code_present": country_code_present,
            "core_enrichment_status": core_enrichment_status,
            "privacy_enrichment_status": privacy_enrichment_status,
        },
        "observation": behavior,
        "region_profile": region,
        "ai_profile": {
            "present": ai_present,
            "ai_anomaly_score": ai_score,
            "windows_seen": ai_windows,
            "anomalous_windows": ai_profile.get("anomalous_windows") if ai_bonus_eligible else None,
            "confidence": _normalize_confidence(ai_profile.get("confidence")) if ai_present else 0,
            "confidence_level": ai_confidence_level,
        },
    }


def classification_input_provenance(
    profile: Mapping[str, Any] | None,
    observation: Mapping[str, Any] | None = None,
    region_profile: Mapping[str, Any] | None = None,
    ai_profile: Mapping[str, Any] | None = None,
    *,
    version: str = CLASSIFICATION_INPUT_VERSION,
) -> dict[str, Any]:
    """Return an explicit input-contract version, canonical projection, and digest."""
    canonical_inputs = canonical_classification_inputs(
        profile, observation, region_profile, ai_profile
    )
    fingerprint_input = json.dumps(
        {"version": version, "canonical_inputs": canonical_inputs},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )
    return {
        "version": version,
        "fingerprint": hashlib.sha256(fingerprint_input.encode("utf-8")).hexdigest(),
        "canonical_inputs": canonical_inputs,
    }
