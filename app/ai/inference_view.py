"""Deterministic, bounded LLM-only view derived from a canonical CasePacket."""

from __future__ import annotations

from collections import Counter
import json
from typing import Any, Mapping


INFERENCE_VIEW_VERSION = "ai-4a4-v2"
INFERENCE_VIEW_CONFIG = {
    "max_input_chars": 3500,
    "max_representative_examples": 6,
    "max_evidence_items": 18,
    "max_evidence_chars": 2400,
    "aggregation_key": ["method", "path", "status"],
    "singleton_count_omitted_as": 1,
}


def estimate_prompt_tokens(*parts: str) -> int:
    """Conservative preflight estimate for the llama.cpp context budget."""
    return (sum(len(part) for part in parts) + 2) // 3


def _evidence_priority(item: Mapping[str, Any]) -> int:
    value = " ".join(str(item.get(key) or "").lower() for key in ("source", "type", "detector", "rule_id"))
    if any(term in value for term in ("rule", "sensitive", "brute", "scan", "burst")):
        return 0
    if "rare" in value:
        return 1
    if any(term in value for term in ("privacy", "reputation", "abuse")):
        return 2
    if any(term in value for term in ("isolation", "anomaly", "ai")):
        return 3
    if any(term in value for term in ("geo", "network", "asn")):
        return 4
    return 5


def _bounded_evidence(case_packet: Mapping[str, Any]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    original = [item for item in case_packet.get("evidence", []) if isinstance(item, Mapping)]
    indexed = list(enumerate(original))
    indexed.sort(key=lambda pair: (_evidence_priority(pair[1]), pair[0], str(pair[1].get("evidence_id") or "")))
    selected: list[dict[str, Any]] = []
    used = 0
    for _, item in indexed:
        if len(selected) >= INFERENCE_VIEW_CONFIG["max_evidence_items"]:
            break
        candidate = json.dumps(dict(item), sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        separator = 1 if selected else 0
        if selected and used + separator + len(candidate) > INFERENCE_VIEW_CONFIG["max_evidence_chars"]:
            continue
        if not selected and len(candidate) > INFERENCE_VIEW_CONFIG["max_evidence_chars"]:
            continue
        selected.append(dict(item))
        used += separator + len(candidate)
    return selected, {"evidence_total": len(original), "evidence_included": len(selected), "evidence_omitted": len(original) - len(selected)}


def build_inference_view(case_packet: Mapping[str, Any]) -> dict[str, Any]:
    """Build a compact request representation without mutating the canonical packet."""
    view = dict(case_packet)
    evidence, evidence_context = _bounded_evidence(case_packet)
    if case_packet.get("evidence"):
        view["evidence"] = evidence
        view["evidence_context"] = evidence_context
    if "representative_requests" not in case_packet:
        return view
    requests = [item for item in case_packet.get("representative_requests", []) if isinstance(item, Mapping)]
    if not requests:
        return view
    counts = Counter(
        (str(item.get("method") or "—"), str(item.get("path") or ""), item.get("status"))
        for item in requests
    )
    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0][0], item[0][1], str(item[0][2])))
    selected_keys = {key for key, _ in ordered}

    view.pop("representative_requests", None)
    view["request_patterns"] = [
        {"method": key[0], "path": key[1], "status": key[2], **({"count": count} if count != 1 else {})}
        for key, count in ordered
    ]
    view["request_context"] = {
        "observed_request_count": len(requests),
        "pattern_count": len(counts),
    }

    examples = []
    seen = set()
    for item in requests:
        key = (str(item.get("method") or "—"), str(item.get("path") or ""), item.get("status"))
        if key in seen:
            continue
        seen.add(key)
        examples.append({"method": key[0], "path": key[1], "status": key[2]})
        if len(examples) >= INFERENCE_VIEW_CONFIG["max_representative_examples"]:
            break
    candidate = {**view, "representative_examples": examples}
    if len(json.dumps(candidate, sort_keys=True, ensure_ascii=False)) <= INFERENCE_VIEW_CONFIG["max_input_chars"]:
        view = candidate
    return view
