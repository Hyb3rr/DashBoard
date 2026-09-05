from app.ai.evaluation import build_review_capture, evaluate_case, evaluate_corpus
from app.ai.reasoning import ReasoningResult
from scripts.ai.evaluate_cases import _load_corpus, benchmark_metadata
from app.ai.providers.llama_cpp import _valid_analysis


PACKET = {"case_id": "case_1", "evidence_fingerprint": "fp_1", "evidence": [{"evidence_id": "ev_1"}]}


def result(content, status="received"):
    raw = {"choices": [{"message": {"content": content}}]} if content is not None else {}
    return ReasoningResult(status, "fp_1", raw)


def test_evaluation_accepts_grounded_output():
    report = evaluate_case(PACKET, result('{"summary":"scan","primary_evidence":[{"evidence_id":"ev_1"}]}'), 12.345)
    assert report["grounded"] is True
    assert report["response_valid_json"] is True
    assert report["latency_ms"] == 12.35


def test_evaluation_rejects_unsupported_duplicate_and_authority_output():
    response = result('{"primary_evidence":["ev_1","ev_1","ev_missing"],"new_classification":"bad","new_risk_score":99}')
    report = evaluate_case(PACKET, response, 1)
    assert report["grounded"] is False
    assert report["unsupported_evidence_ids"] == ["ev_missing"]
    assert report["duplicate_evidence_ids"] is True
    assert report["authority_violation"] is True


def test_evaluation_marks_malformed_and_provider_failure():
    assert evaluate_case(PACKET, result("not-json"), 1)["response_valid_json"] is False
    assert evaluate_case(PACKET, result(None, "timeout"), 1)["provider_status"] == "timeout"


def test_corpus_report_aggregates_grounding_failure_and_latency():
    class FakeProvider:
        def __init__(self): self.calls = 0
        def explain(self, _packet):
            self.calls += 1
            return result('{"primary_evidence":["ev_1"]}') if self.calls == 1 else result('{"primary_evidence":["ev_missing"]}')

    report = evaluate_corpus([PACKET, {**PACKET, "case_id": "case_2"}], FakeProvider())
    assert report["total_cases"] == 2
    assert report["grounded_cases"] == 1
    assert report["grounding_rate"] == 0.5
    assert report["unsupported_evidence_cases"] == 1
    assert report["latency_ms"]["p50"] is not None


def test_evaluation_cli_accepts_frozen_corpus_object(tmp_path):
    path = tmp_path / "corpus.json"
    path.write_text('{"manifest":{"corpus_sha256":"abc","packet_count":1},"cases":[]}', encoding="utf-8")
    cases, manifest = _load_corpus(path)
    assert cases == []
    assert manifest == {"corpus_sha256": "abc", "packet_count": 1}


def test_provider_validation_rejects_unknown_id_and_oversized_output():
    valid = {"summary": "s", "primary_evidence": [{"evidence_id": "ev_unknown", "reason": "r"}], "supporting_evidence": [], "alternative_explanation": "a", "uncertainty": "low", "recommended_investigation": []}
    assert _valid_analysis(valid, {"ev_known"}) is False
    valid["primary_evidence"] = []
    valid["summary"] = "x" * 161
    assert _valid_analysis(valid, {"ev_known"}) is False


def test_benchmark_metadata_hashes_dynamic_schema_per_case():
    metadata = benchmark_metadata({}, None, 120, [{"evidence": [{"evidence_id": "ev_a"}]}])
    assert metadata["schema_scope"] == "dynamic_per_case_packet"
    assert len(metadata["schema_sha256"]) == 64


def test_capture_mode_keeps_only_validated_analysis():
    captured = evaluate_case(PACKET, result('{"summary":"scan","primary_evidence":[{"evidence_id":"ev_1","reason":"rule"}],"supporting_evidence":[],"alternative_explanation":"none","uncertainty":"low","recommended_investigation":[]}'), 12, include_analysis=True)
    assert captured["status"] == "completed"
    assert captured["analysis"]["summary"] == "scan"
    assert captured["validation"]["grounded"] is True
    assert "raw_response" not in captured


def test_evaluation_rejects_evidence_based_analysis_without_citations():
    provider_result = result('{"summary":"scan","primary_evidence":[],"supporting_evidence":[],"alternative_explanation":"none","uncertainty":"moderate","recommended_investigation":[]}')
    report = evaluate_case({**PACKET, "evidence": [{"evidence_id": "ev_1"}]}, provider_result, 12)
    assert report["missing_evidence_references"] is True
    assert report["grounded"] is False


def test_evaluation_rejects_obvious_truncated_text():
    provider_result = result('{"summary":"The activity is consistent with benign traffic, as ","primary_evidence":[{"evidence_id":"ev_1"}],"supporting_evidence":[],"alternative_explanation":"none","uncertainty":"moderate","recommended_investigation":[]}')
    report = evaluate_case({**PACKET, "evidence": [{"evidence_id": "ev_1"}]}, provider_result, 12)
    assert report["incomplete_text"] is True
    assert report["grounded"] is False


def test_evaluation_rejects_trailing_comma_fragment():
    provider_result = result('{"summary":"Rare path observed.","primary_evidence":[{"evidence_id":"ev_1"}],"supporting_evidence":[],"alternative_explanation":"This could be benign activity, such as a new deployment,","uncertainty":"moderate","recommended_investigation":[]}')
    report = evaluate_case({**PACKET, "evidence": [{"evidence_id": "ev_1"}]}, provider_result, 12)
    assert report["incomplete_text"] is True
    assert report["grounded"] is False


def test_review_capture_keeps_validated_analysis_only():
    captured = build_review_capture(
        PACKET,
        result('{"summary":"scan","primary_evidence":[{"evidence_id":"ev_1","reason":"rule"}],"supporting_evidence":[],"alternative_explanation":"none","uncertainty":"low","recommended_investigation":[]}'),
        12,
        "capture-001",
        {"corpus_sha256": "abc"},
    )
    assert captured["status"] == "completed"
    assert captured["analysis"]["summary"] == "scan"
    assert captured["capture_run_id"] == "capture-001"
    assert "raw_response" not in captured


def test_review_capture_does_not_publish_invalid_analysis():
    captured = build_review_capture(PACKET, result('{"summary":"scan","primary_evidence":[{"evidence_id":"ev_missing"}]}'), 12, "capture-001", {})
    assert captured["status"] == "failed"
    assert captured["analysis"] is None
    assert captured["validation"]["grounded"] is False
