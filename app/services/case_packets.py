"""Deterministic, bounded case packets for downstream explainers."""

from __future__ import annotations

import hashlib
import ipaddress
import json
from typing import Any, Iterable
from urllib.parse import urlsplit


MAX_EVIDENCE = 100
MAX_REPRESENTATIVE_REQUESTS = 20
MAX_PATH_LENGTH = 2048
_CLASSIFICATIONS = {"unknown", "good", "low", "medium", "critical"}


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _bounded_text(value: Any, limit: int) -> str:
    return str(value or "")[:limit]


def _safe_path(value: Any) -> str:
    raw = _bounded_text(value, MAX_PATH_LENGTH)
    if not raw:
        return ""
    parsed = urlsplit(raw)
    return _bounded_text(parsed.path or raw.split("?", 1)[0], MAX_PATH_LENGTH)


def _normalise_evidence(items: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, dict):
            raise TypeError("case evidence items must be mappings")
        evidence_id = str(item.get("evidence_id") or "")
        if not evidence_id:
            raise ValueError("case evidence requires evidence_id")
        if evidence_id in seen:
            raise ValueError(f"duplicate evidence_id: {evidence_id}")
        seen.add(evidence_id)
        result.append(dict(item))
        if len(result) >= MAX_EVIDENCE:
            break
    return result


def _normalise_requests(items: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for item in items:
        if not isinstance(item, dict):
            continue
        status = item.get("status")
        result.append({
            "method": _bounded_text(item.get("method") or "—", 16),
            "path": _safe_path(item.get("path")),
            "status": int(status) if isinstance(status, int) and not isinstance(status, bool) else None,
        })
        if len(result) >= MAX_REPRESENTATIVE_REQUESTS:
            break
    return result


def build_case_packet(
    ip: str,
    classification: dict[str, Any],
    window: dict[str, Any],
    traffic_summary: dict[str, Any],
    evidence: Iterable[dict[str, Any]],
    representative_requests: Iterable[dict[str, Any]] = (),
) -> dict[str, Any]:
    """Build bounded, deterministic packet; no database, network, or AI access."""
    subject_ip = str(ipaddress.ip_address(ip))
    label = str(classification.get("label") or "unknown").lower()
    if label not in _CLASSIFICATIONS:
        raise ValueError(f"unsupported classification label: {label}")
    risk_score = int(classification.get("risk_score", classification.get("score", 0)) or 0)
    if not 0 <= risk_score <= 100:
        raise ValueError("classification risk_score must be between 0 and 100")
    packet = {
        "subject": {"ip": subject_ip},
        "classification": {
            "label": label,
            "risk_score": risk_score,
            "confidence": int(classification.get("confidence", 0) or 0),
        },
        "window": {"start": str(window.get("start") or ""), "end": str(window.get("end") or "")},
        "traffic_summary": {
            key: traffic_summary.get(key, 0)
            for key in ("requests", "unique_paths", "status_4xx_ratio")
        },
        "evidence": _normalise_evidence(evidence),
        "representative_requests": _normalise_requests(representative_requests),
    }
    fingerprint_payload = {**packet, "evidence": [{k: v for k, v in item.items() if k != "freshness"} for item in packet["evidence"]]}
    fingerprint = hashlib.sha256(_canonical(fingerprint_payload).encode("utf-8")).hexdigest()[:24]
    return {"case_id": f"case_{fingerprint}", "evidence_fingerprint": fingerprint, **packet}


def build_trigger_identity(packet: dict[str, Any]) -> dict[str, str]:
    """Build stable deduplication identity for a future semantic trigger.

    Moving observation windows and request samples are intentionally excluded;
    the canonical packet and its fingerprint remain unchanged.
    """
    subject = packet.get("subject") or {}
    classification = packet.get("classification") or {}
    evidence = [
        {key: value for key, value in item.items() if key != "freshness"}
        for item in packet.get("evidence") or []
    ]
    identity_payload = {
        "ip": subject.get("ip"),
        "classification": classification,
        "evidence": evidence,
    }
    fingerprint = hashlib.sha256(_canonical(identity_payload).encode("utf-8")).hexdigest()[:24]
    return {"case_id": f"case_trigger_{fingerprint}", "evidence_fingerprint": fingerprint}


def build_live_case_packet(ip: str, snapshot: dict[str, Any], traffic: dict[str, Any], start: Any, end: Any) -> dict[str, Any]:
    """Build a bounded live packet from already-read snapshots.

    Database and ClickHouse access stays in the outer router; this function
    only adapts read models into the canonical deterministic packet.
    """
    classification = snapshot.get("classification") or {}
    observation = snapshot.get("observation") or {}
    evidence: list[dict[str, Any]] = []
    raw_evidence = list(classification.get("evidence") or []) + list(observation.get("rare_path_evidence") or [])
    for index, item in enumerate(raw_evidence):
        if isinstance(item, dict):
            adapted = dict(item)
            if not adapted.get("evidence_id"):
                digest = hashlib.sha256(_canonical(adapted).encode("utf-8")).hexdigest()[:16]
                adapted["evidence_id"] = f"ev_live_{digest}"
            evidence.append(adapted)
        else:
            evidence.append({"evidence_id": f"ev_live_{index:03d}", "source": "classification", "description": str(item)})
    return build_case_packet(
        ip,
        {"label": classification.get("label"), "score": classification.get("score", 0), "confidence": classification.get("confidence", 0)},
        {"start": start, "end": end},
        {"requests": observation.get("requests", traffic.get("total_requests", 0)), "unique_paths": observation.get("unique_paths", 0), "status_4xx_ratio": (int(observation.get("status_4xx", 0)) / max(1, int(observation.get("requests", 0))))},
        evidence,
        traffic.get("recent_requests") or (),
    )
