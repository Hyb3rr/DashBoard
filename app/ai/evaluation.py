"""Offline evaluation logic for local case explanations."""

from __future__ import annotations

import json
from statistics import median
from time import perf_counter
from typing import Any, Iterable

from .reasoning import LocalReasoningProvider, ReasoningResult


def _content(result: ReasoningResult) -> dict[str, Any] | None:
    raw = result.raw_response or {}
    choices = raw.get("choices") if isinstance(raw, dict) else None
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        return None
    message = choices[0].get("message")
    value = message.get("content") if isinstance(message, dict) else None
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return None
        return parsed if isinstance(parsed, dict) else None
    return None


def _evidence_ids(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item if isinstance(item, str) else str(item["evidence_id"]) for item in value if isinstance(item, str) or isinstance(item, dict) and item.get("evidence_id")]


def evaluate_case(case_packet: dict[str, Any], result: ReasoningResult, latency_ms: float, include_analysis: bool = False) -> dict[str, Any]:
    packet_ids = {str(item["evidence_id"]) for item in case_packet.get("evidence", []) if isinstance(item, dict) and item.get("evidence_id")}
    analysis = _content(result) if result.status == "received" else None
    cited = _evidence_ids((analysis or {}).get("primary_evidence")) + _evidence_ids((analysis or {}).get("supporting_evidence"))
    unsupported = sorted(set(cited) - packet_ids)
    duplicate = len(cited) != len(set(cited))
    missing_references = bool(packet_ids and analysis is not None and _requires_evidence_reference(analysis) and not cited)
    incomplete_text = _analysis_has_incomplete_text(analysis)
    authority_violation = any(key in (analysis or {}) for key in ("new_classification", "new_risk_score"))
    report = {
        "case_id": case_packet.get("case_id"), "evidence_fingerprint": case_packet.get("evidence_fingerprint"),
        "provider_status": result.status, "latency_ms": round(max(0.0, latency_ms), 2),
        "response_valid_json": analysis is not None, "grounded": analysis is not None and not unsupported and not duplicate and not authority_violation and not missing_references and not incomplete_text,
        "unsupported_evidence_ids": unsupported, "duplicate_evidence_ids": duplicate, "authority_violation": authority_violation,
        "missing_evidence_references": missing_references, "incomplete_text": incomplete_text,
    }
    if include_analysis:
        report.update({
            "status": "completed" if analysis is not None and result.status == "received" else "failed",
            "analysis": analysis,
            "validation": {
                "grounded": report["grounded"],
                "unsupported_evidence_ids": unsupported,
                "duplicate_evidence_ids": duplicate,
                "authority_violation": authority_violation,
                "missing_evidence_references": missing_references,
                "incomplete_text": incomplete_text,
            },
        })
    return report


def _analysis_has_incomplete_text(analysis: dict[str, Any] | None) -> bool:
    if not analysis:
        return False
    values = [analysis.get("summary"), analysis.get("alternative_explanation"), *(analysis.get("recommended_investigation") or [])]
    return any(isinstance(value, str) and _looks_truncated(value) for value in values)


def _looks_truncated(value: str) -> bool:
    stripped = value.rstrip()
    if stripped != value or "<span" in value or "</" in value or stripped.endswith((",", ":", ";")):
        return True
    return stripped.lower().split()[-1:] in [["as"], ["and"], ["or"], ["the"], ["a"], ["an"], ["of"], ["to"], ["for"], ["with"], ["from"], ["any"], ["known"], ["anom"]]


def _requires_evidence_reference(analysis: dict[str, Any]) -> bool:
    text = " ".join([analysis.get("summary", ""), analysis.get("alternative_explanation", ""), *(analysis.get("recommended_investigation") or [])]).lower()
    return any(term in text for term in ("evidence", "request", "path", "probe", "rare", "scan", "traffic", "suspicious", "malicious", "anomal"))


def build_review_capture(
    case_packet: dict[str, Any],
    result: ReasoningResult,
    latency_ms: float,
    capture_run_id: str,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    """Build one immutable per-case review artifact from validated output only."""
    report = evaluate_case(case_packet, result, latency_ms, include_analysis=True)
    completed = report["status"] == "completed" and report["validation"]["grounded"]
    artifact = {
        "case_id": report["case_id"],
        "evidence_fingerprint": report["evidence_fingerprint"],
        "capture_run_id": capture_run_id,
        "latency_ms": report["latency_ms"],
        "status": "completed" if completed else "failed",
        "analysis": report["analysis"] if completed else None,
        "validation": report["validation"],
        "provenance": metadata,
    }
    if result.error:
        artifact["error"] = result.error
    return artifact


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, round(len(ordered) * percentile + 0.5) - 1))
    return round(ordered[index], 2)


def evaluate_corpus(cases: Iterable[dict[str, Any]], provider: LocalReasoningProvider, include_analysis: bool = False) -> dict[str, Any]:
    reports = []
    for item in cases:
        packet = item.get("case_packet", item)
        started = perf_counter()
        result = provider.explain(packet)
        reports.append(evaluate_case(packet, result, (perf_counter() - started) * 1000, include_analysis))
    latencies = [float(item["latency_ms"]) for item in reports]
    total = len(reports)
    grounded = sum(item["grounded"] for item in reports)
    return {
        "total_cases": total, "grounded_cases": grounded, "grounding_rate": round(grounded / total, 4) if total else 0,
        "malformed_response_cases": sum(not item["response_valid_json"] for item in reports),
        "unsupported_evidence_cases": sum(bool(item["unsupported_evidence_ids"]) for item in reports),
        "authority_violation_cases": sum(item["authority_violation"] for item in reports),
        "provider_failures": sum(item["provider_status"] != "received" for item in reports),
        "latency_ms": {"p50": _percentile(latencies, 0.50), "p95": _percentile(latencies, 0.95), "median": round(median(latencies), 2) if latencies else None},
        "cases": reports,
    }
