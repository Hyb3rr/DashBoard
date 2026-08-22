"""Canonical, window-aware classification snapshot.

Routes, background consumers and alerting must use this module so they never
silently classify the same IP from different observation windows.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from ..core.json_utils import decode
from ..core.intelligence import classify_ip
from ..core.rules import ruleset_hash


@dataclass(frozen=True)
class ClassificationSnapshot:
    ip: str
    profile: dict
    observation: dict
    region: dict
    ai_profile: dict | None
    classification: dict
    window: str = "24h"

    def to_dict(self) -> dict:
        result = dict(self.classification)
        result.update({
            "ip": self.ip,
            "observation_window": self.window,
            "observation": self.observation,
            "region": self.region,
            "ai_profile": self.ai_profile,
        })
        return result


def detection_snapshot(conn, ip: str, window: str = "24h") -> dict:
    if window not in {"1h", "24h"}:
        raise ValueError("window must be 1h or 24h")
    row = conn.execute("SELECT * FROM ip_observations WHERE ip=?", (ip,)).fetchone()
    if not row:
        return {"detections": [], "ruleset_hash": None, "evaluated_at": None, "window": window}
    suffix = "1h" if window == "1h" else "24h"
    return {
        "detections": decode(row[f"detections_{suffix}_json"]),
        "ruleset_hash": row[f"ruleset_hash_{suffix}"],
        "evaluated_at": row[f"evaluated_at_{suffix}"],
        "window": window,
    }


def _decode_profile(row) -> dict:
    data = dict(row) if row else {}
    for column, key, fallback in (
        ("evidence_json", "evidence", []),
        ("source_json", "sources", []),
        ("identity_evidence_json", "identity_evidence", []),
        ("reputation_json", "reputation", []),
        ("provider_errors_json", "provider_errors", []),
        ("provider_status_json", "provider_status", {}),
        ("field_sources_json", "field_sources", {}),
    ):
        if column in data:
            data[key] = decode(data.pop(column))
        else:
            data[key] = fallback
    return data


def _observation(row) -> dict:
    source = dict(row) if row else {}
    recent_available = source.get("recent_updated_at") is not None
    result = {
        "behavior_score": source.get("behavior_score", 0),
        "recent_behavior_score": source.get("behavior_score_recent", source.get("behavior_score", 0)) if recent_available else source.get("behavior_score", 0),
        "requests": source.get("requests", 0),
        "recent_requests": source.get("recent_requests", source.get("requests", 0)) if recent_available else source.get("requests", 0),
        "recent_sensitive_probe_requests": source.get("recent_sensitive_probe_requests", source.get("sensitive_probe_requests", 0)) if recent_available else source.get("sensitive_probe_requests", 0),
        "recent_status_2xx": source.get("recent_status_2xx", source.get("status_2xx", 0)) if recent_available else source.get("status_2xx", 0),
        "recent_status_3xx": source.get("recent_status_3xx", source.get("status_3xx", 0)) if recent_available else source.get("status_3xx", 0),
        "recent_status_4xx": source.get("recent_status_4xx", source.get("status_4xx", 0)) if recent_available else source.get("status_4xx", 0),
        "recent_status_5xx": source.get("recent_status_5xx", source.get("status_5xx", 0)) if recent_available else source.get("status_5xx", 0),
        "status_4xx": source.get("status_4xx", 0),
        "status_5xx": source.get("status_5xx", 0),
        "unique_paths": source.get("unique_paths", 0),
        "wp_login_requests": source.get("wp_login_requests", 0),
        "sensitive_probe_requests": source.get("sensitive_probe_requests", 0),
        "bot_requests": source.get("bot_requests", 0),
        "bucket_history_hours": source.get("bucket_history_hours"),
        "rule_coverage": source.get("rule_coverage"),
    }
    for column, key, fallback in (
        ("behavior_evidence_recent_json", "behavior_evidence_recent", []),
        ("behavior_evidence_json", "behavior_evidence_lifetime", []),
        ("detections_recent_json", "detections_recent", []),
        ("detections_1h_json", "detections_1h", []),
        ("detections_24h_json", "detections_24h", []),
        ("detections_json", "detections", []),
    ):
        result[key] = decode(source.get(column)) if column in source else fallback
        if result[key] is None:
            result[key] = fallback
    result["behavior_evidence"] = (
        result["behavior_evidence_recent"] if recent_available else result["behavior_evidence_lifetime"]
    )
    for field in ("ruleset_hash", "ruleset_hash_1h", "ruleset_hash_24h", "evaluated_at", "evaluated_at_1h", "evaluated_at_24h"):
        result[field] = source.get(field)
    return result


def build_classification_snapshot(conn, ip: str) -> ClassificationSnapshot:  # pragma: no cover
    """Deprecated: SQLite-backed snapshot. Use StateRepository in live mode."""
    raise NotImplementedError("SQLite removed – use StateRepository for classification snapshots")
