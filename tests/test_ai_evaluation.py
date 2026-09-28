import hashlib
import json

from app.ai.evaluation import build_review_capture, evaluate_case, evaluate_corpus
from app.ai.reasoning import ReasoningResult
from scripts.ai.evaluate_cases import (
    DEFAULT_CONFIGURED_CONTEXT_SIZE,
    OFFLINE_EVALUATION_TIMEOUT_SECONDS,
    _build_report,
    _canonical,
    _capture_metadata,
    _load_corpus,
    benchmark_metadata,
)
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


def test_evaluation_metadata_matches_provider_token_budget_without_inference(monkeypatch):
    import argparse
    import scripts.ai.evaluate_cases as evaluate_cases

    monkeypatch.delenv("LOCAL_REASONING_MAX_TOKENS", raising=False)
    monkeypatch.delenv("FOUNDATION_SEC_CONTEXT_SIZE", raising=False)
    monkeypatch.setattr(evaluate_cases, "_load_corpus", lambda _path: ([], {}))
    monkeypatch.setattr(evaluate_cases, "_runtime_version", lambda _binary: "test")
    observed = {}

    def fake_evaluate(_cases, provider, _capture):
        observed["provider_max_tokens"] = provider.max_tokens
        return {}

    monkeypatch.setattr(evaluate_cases, "evaluate_corpus", fake_evaluate)
    report = _build_report(argparse.Namespace(
        cases="unused.json",
        endpoint="http://127.0.0.1:8081/v1/chat/completions",
        model="test-model",
        timeout=OFFLINE_EVALUATION_TIMEOUT_SECONDS,
        capture_analysis=False,
        model_path=None,
        run_id="test",
    ))

    assert observed["provider_max_tokens"] == 768
    assert report["benchmark_metadata"]["max_tokens"] == observed["provider_max_tokens"]
    assert report["benchmark_metadata"]["timeout_seconds"] == 30
    assert report["benchmark_metadata"]["context_size"] == DEFAULT_CONFIGURED_CONTEXT_SIZE
    assert report["benchmark_metadata"]["runtime_profile"] == "offline_evaluation"
    assert report["benchmark_metadata"]["model_name"] == "test-model"


def test_manual_capture_metadata_uses_resolved_cli_configuration_without_inference(
    monkeypatch, tmp_path
):
    import json
    import sys
    import scripts.ai.capture_case_review as capture
    import scripts.ai.evaluate_cases as evaluate_cases

    cases_path = tmp_path / "cases.json"
    cases_path.write_text(json.dumps({"cases": [{"case_packet": {"case_id": "case-1"}}]}))
    model_path = tmp_path / "model.gguf"
    model_path.write_bytes(b"fixture")
    output_path = tmp_path / "captures"
    monkeypatch.setenv("LOCAL_REASONING_MAX_TOKENS", "256")
    monkeypatch.setenv("FOUNDATION_SEC_CONTEXT_SIZE", "4096")
    monkeypatch.setattr(evaluate_cases, "_runtime_version", lambda _binary: "test")
    monkeypatch.setattr(
        capture,
        "_capture_one",
        lambda _case, _args, _metadata: {
            "status": "completed",
            "validation": {"grounded": True},
        },
    )
    monkeypatch.setattr(sys, "argv", [
        "capture_case_review",
        str(cases_path),
        "--output-dir", str(output_path),
        "--run-id", "test-run",
        "--model-path", str(model_path),
        "--timeout", "90",
        "--max-tokens", "512",
        "--context-size", "6144",
        "--gpu-layers", "2",
        "--threads", "4",
        "--ready-attempts", "120",
        "--ready-interval", "0.25",
    ])

    assert capture.main() == 0
    metadata = json.loads((output_path / "manifest.json").read_text())["metadata"]
    assert metadata["timeout_seconds"] == 90
    assert metadata["max_tokens"] == 512
    assert metadata["context_size"] == 6144
    assert metadata["gpu_layers"] == 2
    assert metadata["threads"] == 4
    assert metadata["ready_attempts"] == 120
    assert metadata["ready_interval_seconds"] == 0.25
    assert metadata["runtime_profile"] == "manual_standalone_capture"
    assert metadata["model_name"] == "Foundation-Sec-8B-Reasoning"
    assert metadata["host"] == "127.0.0.1"
    assert metadata["server_binary"] == "llama-server"


def test_offline_and_manual_capture_profiles_remain_explicit_and_distinct():
    from scripts.ai.capture_case_review import (
        CAPTURE_CONTEXT_SIZE,
        CAPTURE_MAX_TOKENS,
        CAPTURE_READY_ATTEMPTS,
        CAPTURE_TIMEOUT_SECONDS,
    )

    assert OFFLINE_EVALUATION_TIMEOUT_SECONDS == 30
    assert (CAPTURE_TIMEOUT_SECONDS, CAPTURE_MAX_TOKENS, CAPTURE_CONTEXT_SIZE, CAPTURE_READY_ATTEMPTS) == (
        120, 256, 4096, 60
    )


def test_capture_metadata_hashes_report_before_adding_capture_metadata():
    report = {"total_cases": 1, "grounded_cases": 1}

    metadata = _capture_metadata(report, "review-run")

    assert metadata["run_id"] == "review-run"
    assert metadata["raw_provider_response_saved"] is False
    assert metadata["report_sha256"] == hashlib.sha256(
        _canonical(report).encode("utf-8")
    ).hexdigest()


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


def test_evaluation_accepts_complete_text_ending_in_known():
    provider_result = result('{"summary":"ASN is already known","primary_evidence":[{"evidence_id":"ev_1","reason":"ASN signal"}],"supporting_evidence":[],"alternative_explanation":"Could be routine network activity.","uncertainty":"moderate","recommended_investigation":[]}')

    report = evaluate_case(PACKET, provider_result, 12)

    assert report["incomplete_text"] is False
    assert report["grounded"] is True


def test_evaluation_still_rejects_obvious_incomplete_fragments():
    for fragment in ("Evidence indicates activity from", "Repeated probes,"):
        provider_result = result(json.dumps({
            "summary": fragment,
            "primary_evidence": [{"evidence_id": "ev_1"}],
            "supporting_evidence": [],
            "alternative_explanation": "Could be routine network activity.",
            "uncertainty": "moderate",
            "recommended_investigation": [],
        }))
        report = evaluate_case(PACKET, provider_result, 12)
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
