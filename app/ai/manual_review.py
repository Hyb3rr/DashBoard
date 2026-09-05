"""Deterministic selection and formatting for human review artifacts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable


REVIEW_RUBRIC = (
    "evidence_interpretation",
    "reasoning_relevance",
    "evidence_sufficiency",
    "alternative_explanation",
    "investigation_usefulness",
    "uncertainty_calibration",
    "overclaiming",
)
SCORE_DIMENSIONS = REVIEW_RUBRIC[:-1]


def _valid_capture(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("status") != "completed" or not value.get("validation", {}).get("grounded"):
        return None
    return value if isinstance(value.get("analysis"), dict) else None


def select_earliest_validated(cases: Iterable[dict[str, Any]], capture_dirs: Iterable[Path]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Select the first validated capture in supplied attempt order."""
    directories = list(capture_dirs)
    selected: list[dict[str, Any]] = []
    unavailable: list[dict[str, Any]] = []
    for item in cases:
        packet = item.get("case_packet", item)
        case_id = str(packet.get("case_id"))
        capture = next(
            (candidate for directory in directories if (candidate := _valid_capture(directory / f"{case_id}.json")) is not None),
            None,
        )
        if capture is None:
            unavailable.append({"case_id": case_id, "status": "NO_VALIDATED_OUTPUT"})
            continue
        selected.append({
            "case_id": case_id,
            "evidence_fingerprint": packet.get("evidence_fingerprint"),
            "case_packet": packet,
            "capture_run_id": capture.get("capture_run_id"),
            "analysis": capture["analysis"],
            "validation": capture["validation"],
            "latency_ms": capture.get("latency_ms"),
            "review": {key: None for key in REVIEW_RUBRIC},
            "review_notes": None,
        })
    return selected, unavailable


def build_manual_review_packet(cases: list[dict[str, Any]], capture_dirs: list[Path], provenance: dict[str, Any]) -> dict[str, Any]:
    selected, unavailable = select_earliest_validated(cases, capture_dirs)
    return {
        "format_version": "ai-4c2-v1",
        "coverage": {"total_cases": len(cases), "validated_cases": len(selected), "unavailable_cases": len(unavailable)},
        "rubric": list(REVIEW_RUBRIC),
        "provenance": provenance,
        "cases": selected,
        "unavailable": unavailable,
    }


def aggregate_manual_scores(review_packet: dict[str, Any], scores: list[dict[str, Any]]) -> dict[str, Any]:
    """Validate and aggregate human scores without scoring unavailable cases."""
    expected = {item["case_id"] for item in review_packet.get("cases", [])}
    received = {item.get("case_id") for item in scores}
    if received != expected or len(received) != len(scores):
        raise ValueError("scores must contain exactly one record for every validated case")
    normalized = []
    for item in scores:
        for key in SCORE_DIMENSIONS:
            if not isinstance(item.get(key), int) or isinstance(item.get(key), bool) or item[key] not in {0, 1, 2}:
                raise ValueError(f"{item.get('case_id')}: {key} must be 0, 1, or 2")
        if not isinstance(item.get("overclaiming"), bool):
            raise ValueError(f"{item.get('case_id')}: overclaiming must be boolean")
        normalized.append({"case_id": item["case_id"], "scores": {key: item[key] for key in SCORE_DIMENSIONS}, "overclaiming": item["overclaiming"], "notes": item.get("notes")})
    totals = [sum(item["scores"].values()) for item in normalized]
    means = {key: round(sum(item["scores"][key] for item in normalized) / len(normalized), 2) for key in SCORE_DIMENSIONS}
    ordered = sorted(totals)
    middle = ordered[len(ordered) // 2] if len(ordered) % 2 else (ordered[len(ordered) // 2 - 1] + ordered[len(ordered) // 2]) / 2
    return {
        "reviewer_count": 1,
        "reviewer_limitation": "single reviewer; no inter-rater agreement measured",
        "case_count": len(normalized),
        "median_total_quality": middle,
        "mean_dimension_scores": means,
        "overclaiming_count": sum(item["overclaiming"] for item in normalized),
        "overclaiming_rate": round(sum(item["overclaiming"] for item in normalized) / len(normalized), 4),
        "scores": normalized,
    }
