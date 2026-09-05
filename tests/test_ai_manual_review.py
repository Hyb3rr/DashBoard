import json

import pytest

from app.ai.manual_review import REVIEW_RUBRIC, aggregate_manual_scores, build_manual_review_packet, select_earliest_validated


PACKET = {"case_id": "case_1", "evidence_fingerprint": "fp_1", "evidence": [{"evidence_id": "ev_1"}]}
ANALYSIS = {"summary": "scan", "primary_evidence": [], "supporting_evidence": [], "alternative_explanation": "none", "uncertainty": "low", "recommended_investigation": []}


def write_capture(directory, case_id, run_id, valid=True):
    (directory / f"{case_id}.json").write_text(json.dumps({
        "case_id": case_id, "capture_run_id": run_id, "status": "completed" if valid else "failed",
        "analysis": ANALYSIS if valid else None, "validation": {"grounded": valid}, "latency_ms": 1,
    }), encoding="utf-8")


def test_selects_earliest_validated_capture(tmp_path):
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir(); second.mkdir()
    write_capture(first, "case_1", "run-1", valid=False)
    write_capture(second, "case_1", "run-2", valid=True)
    selected, unavailable = select_earliest_validated([PACKET], [first, second])
    assert selected[0]["capture_run_id"] == "run-2"
    assert unavailable == []


def test_unavailable_case_is_not_scored(tmp_path):
    packet = build_manual_review_packet([PACKET], [tmp_path / "missing"], {"corpus_sha256": "abc"})
    assert packet["coverage"] == {"total_cases": 1, "validated_cases": 0, "unavailable_cases": 1}
    assert packet["unavailable"] == [{"case_id": "case_1", "status": "NO_VALIDATED_OUTPUT"}]


def test_review_packet_contains_frozen_rubric_and_no_raw_response(tmp_path):
    captures = tmp_path / "captures"
    captures.mkdir()
    write_capture(captures, "case_1", "run-1", valid=True)
    packet = build_manual_review_packet([PACKET], [captures], {})
    assert packet["rubric"] == list(REVIEW_RUBRIC)
    assert packet["cases"][0]["review"]["overclaiming"] is None
    assert "raw_response" not in packet["cases"][0]


def test_score_aggregation_validates_and_aggregates(tmp_path):
    captures = tmp_path / "captures"
    captures.mkdir()
    write_capture(captures, "case_1", "run-1", valid=True)
    packet = build_manual_review_packet([PACKET], [captures], {})
    score = {"case_id": "case_1", **{key: 2 for key in REVIEW_RUBRIC[:-1]}, "overclaiming": False, "notes": "clear"}
    result = aggregate_manual_scores(packet, [score])
    assert result["median_total_quality"] == 12
    assert result["overclaiming_count"] == 0


def test_score_aggregation_rejects_unavailable_or_invalid_scores():
    with pytest.raises(ValueError):
        aggregate_manual_scores({"cases": []}, [{"case_id": "case_1"}])
