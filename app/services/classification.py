"""Canonical, window-aware classification snapshot.

Routes, background consumers and alerting must use this module so they never
silently classify the same IP from different observation windows.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..core.correlation import cluster_for_ip
from ..core.db import decode, region_profile
from ..core.intelligence import classify_ip
from ..core.rules import ruleset_hash


@dataclass(frozen=True)
class ClassificationSnapshot:
    ip: str
    profile: dict
    observation: dict
    region: dict
    ai_profile: dict | None
    cluster: dict | None
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
            "cluster": self.cluster,
        })
        return result


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
        ("detections_json", "detections", []),
    ):
        result[key] = decode(source.get(column)) if column in source else fallback
        if result[key] is None:
            result[key] = fallback
    result["behavior_evidence"] = (
        result["behavior_evidence_recent"] if recent_available else result["behavior_evidence_lifetime"]
    )
    return result


def build_classification_snapshot(conn, ip: str) -> ClassificationSnapshot:
    profile = _decode_profile(conn.execute("SELECT * FROM ip_profiles WHERE ip=?", (ip,)).fetchone())
    profile.setdefault("ip", ip)
    observation = _observation(conn.execute("SELECT * FROM ip_observations WHERE ip=?", (ip,)).fetchone())
    region = region_profile(conn, profile.get("country_code")) or {}
    ai_row = conn.execute("SELECT * FROM ip_ai_scores WHERE ip=?", (ip,)).fetchone()
    ai_profile = dict(ai_row) if ai_row else None
    if ai_profile:
        ai_profile["ai_evidence"] = decode(ai_profile.pop("ai_evidence_json", "[]"))
    cluster = cluster_for_ip(conn, ip)
    classification = classify_ip(profile, observation, region, ai_profile, cluster)
    classification["ruleset_hash"] = ruleset_hash()
    classification["detections_recent"] = observation.get("detections_recent", [])
    return ClassificationSnapshot(ip, profile, observation, region, ai_profile, cluster, classification)
