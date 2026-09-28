"""Normalize persisted state into a storage-independent semantic contract."""

from __future__ import annotations

import json
from typing import Any, Iterable


SEMANTIC_FIELDS = (
    "requests", "status_2xx", "status_3xx", "status_4xx", "status_5xx",
    "status_403", "status_404", "post_requests", "sensitive_hits",
    "wp_login_hits", "bot_hits", "unique_paths", "behavior_score",
    "behavior_level", "recent_requests", "recent_behavior_score",
    "detections_1h", "detections_24h", "classification_label",
    "classification_score", "classification_confidence", "alert_generated",
)


_OBSERVATION_FIELDS = {
    "requests": "requests",
    "status_2xx": "status_2xx",
    "status_3xx": "status_3xx",
    "status_4xx": "status_4xx",
    "status_5xx": "status_5xx",
    "status_403": "status_403",
    "status_404": "status_404",
    "post_requests": "post_requests",
    "sensitive_hits": "sensitive_probe_requests",
    "wp_login_hits": "wp_login_requests",
    "bot_hits": "bot_requests",
    "unique_paths": "unique_paths",
    "behavior_score": "behavior_score",
    "recent_requests": "recent_requests",
    "recent_behavior_score": "recent_behavior_score",
}


def _state_count(observation: dict[str, Any], value: dict[str, Any], field: str, source_field: str | None = None) -> int:
    """Read a semantic count from its observation field or top-level fallback."""
    return int(observation.get(source_field or field) or value.get(field) or 0)


def _state_detections(name: str, detections: dict[str, Any], observation: dict[str, Any]) -> list[tuple]:
    """Normalize detections from the current or legacy observation shape."""
    return normalize_detections(detections.get(name, observation.get(name, [])) or [])


def normalize_state(value: dict[str, Any]) -> dict[str, Any]:
    """Keep comparable security semantics while dropping storage-specific fields."""
    observation = value.get("observation") or value.get("observation_payload") or {}
    classification = value.get("classification") or {}
    detections = value.get("detections") or {}
    if not isinstance(detections, dict):
        detections = {}

    normalized = {field: _state_count(observation, value, field, source_field) for field, source_field in _OBSERVATION_FIELDS.items()}
    normalized.update({
        "behavior_level": observation.get("behavior_level") or value.get("behavior_level"),
        "detections_1h": _state_detections("detections_1h", detections, observation),
        "detections_24h": _state_detections("detections_24h", detections, observation),
        "classification_label": classification.get("label") or value.get("label"),
        "classification_score": int(classification.get("score") or value.get("classification_score") or 0),
        "classification_confidence": int(classification.get("confidence") or value.get("classification_confidence") or 0),
        "alert_generated": bool(value.get("alert_generated", False)),
    })
    return normalized


def semantic_diff(left: dict[str, Any], right: dict[str, Any]) -> dict[str, tuple[Any, Any]]:
    """Return semantic fields whose normalized values differ."""
    a, b = normalize_state(left), normalize_state(right)
    return {key: (a[key], b[key]) for key in SEMANTIC_FIELDS if a[key] != b[key]}


def normalize_detection(value: Any) -> tuple:
    """Normalize one detection across persisted JSON representations."""
    if isinstance(value, str):
        return (value,)
    if not isinstance(value, dict):
        return (str(value),)
    evidence = value.get("evidence")
    evidence = json.dumps(evidence, sort_keys=True, separators=(",", ":"), default=str)
    return (
        value.get("id") or value.get("rule_id"),
        value.get("window"),
        int(value.get("points") or 0),
        value.get("technique") or value.get("mitre_technique"),
        evidence,
    )


def normalize_detections(values: Iterable[Any]) -> list[tuple]:
    """Return detections in stable order for semantic comparison."""
    return sorted((normalize_detection(value) for value in values), key=str)


def semantic_diff_by_ip(left: dict[str, dict[str, Any]], right: dict[str, dict[str, Any]]) -> dict[str, dict[str, tuple[Any, Any]]]:
    """Return a stable, human-readable semantic diff keyed by IP."""
    diff: dict[str, dict[str, tuple[Any, Any]]] = {}
    for ip in sorted(set(left) | set(right)):
        item = semantic_diff(left.get(ip, {}), right.get(ip, {}))
        if item:
            diff[ip] = item
    return diff
