"""Semantic parity helpers for the SQLite-to-split cutover."""

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


def normalize_state(value: dict[str, Any]) -> dict[str, Any]:
    """Drop storage-specific ids/timestamps and keep comparable semantics."""
    observation = value.get("observation") or value.get("observation_payload") or {}
    classification = value.get("classification") or {}
    detections = value.get("detections") or {}
    if not isinstance(detections, dict):
        detections = {}
    def detection_values(name: str) -> list[tuple]:
        raw = detections.get(name, observation.get(name, []))
        return normalize_detections(raw or [])
    return {
        "requests": int(observation.get("requests") or value.get("requests") or 0),
        "status_2xx": int(observation.get("status_2xx") or value.get("status_2xx") or 0),
        "status_3xx": int(observation.get("status_3xx") or value.get("status_3xx") or 0),
        "status_4xx": int(observation.get("status_4xx") or value.get("status_4xx") or 0),
        "status_5xx": int(observation.get("status_5xx") or value.get("status_5xx") or 0),
        "status_403": int(observation.get("status_403") or value.get("status_403") or 0),
        "status_404": int(observation.get("status_404") or value.get("status_404") or 0),
        "post_requests": int(observation.get("post_requests") or value.get("post_requests") or 0),
        "sensitive_hits": int(observation.get("sensitive_probe_requests") or value.get("sensitive_hits") or 0),
        "wp_login_hits": int(observation.get("wp_login_requests") or value.get("wp_login_hits") or 0),
        "bot_hits": int(observation.get("bot_requests") or value.get("bot_hits") or 0),
        "unique_paths": int(observation.get("unique_paths") or value.get("unique_paths") or 0),
        "behavior_score": int(observation.get("behavior_score") or value.get("behavior_score") or 0),
        "behavior_level": observation.get("behavior_level") or value.get("behavior_level"),
        "recent_requests": int(observation.get("recent_requests") or value.get("recent_requests") or 0),
        "recent_behavior_score": int(observation.get("recent_behavior_score") or value.get("recent_behavior_score") or 0),
        "detections_1h": detection_values("detections_1h"),
        "detections_24h": detection_values("detections_24h"),
        "classification_label": classification.get("label") or value.get("label"),
        "classification_score": int(classification.get("score") or value.get("classification_score") or 0),
        "classification_confidence": int(classification.get("confidence") or value.get("classification_confidence") or 0),
        "alert_generated": bool(value.get("alert_generated", False)),
    }


def semantic_diff(left: dict[str, Any], right: dict[str, Any]) -> dict[str, tuple[Any, Any]]:
    a, b = normalize_state(left), normalize_state(right)
    return {key: (a[key], b[key]) for key in SEMANTIC_FIELDS if a[key] != b[key]}


def normalize_detection(value: Any) -> tuple:
    """Make rule output comparable across JSONB/SQLite representations."""
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
    return sorted((normalize_detection(value) for value in values), key=str)


def semantic_diff_by_ip(left: dict[str, dict[str, Any]], right: dict[str, dict[str, Any]]) -> dict[str, dict[str, tuple[Any, Any]]]:
    """Return a stable, human-readable semantic diff keyed by IP."""
    diff: dict[str, dict[str, tuple[Any, Any]]] = {}
    for ip in sorted(set(left) | set(right)):
        item = semantic_diff(left.get(ip, {}), right.get(ip, {}))
        if item:
            diff[ip] = item
    return diff
