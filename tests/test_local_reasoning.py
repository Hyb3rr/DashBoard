import json
import os
import subprocess
import sys
from urllib.error import HTTPError, URLError

import pytest

from app.ai.providers.llama_cpp import (
    ANALYSIS_SCHEMA,
    SYSTEM_PROMPT,
    LlamaCppHttpProvider,
    _analysis_validation_error,
    _valid_analysis,
    build_analysis_schema,
)
from app.ai.inference_view import build_inference_view


PACKET = {"case_id": "case_1", "evidence_fingerprint": "fp_1", "subject": {"ip": "203.0.113.10"}}


def test_provider_rejects_non_local_endpoint():
    with pytest.raises(ValueError, match="localhost HTTP"):
        LlamaCppHttpProvider("http://example.com/v1/chat/completions")


def _allow_provider_request(monkeypatch, budget="100000"):
    monkeypatch.setenv("LOCAL_REASONING_MAX_INPUT_TOKENS", budget)


def test_provider_posts_structured_untrusted_packet(monkeypatch):
    _allow_provider_request(monkeypatch)
    captured = {}

    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self): return b'{"choices": [{"finish_reason": "stop", "message": {"content": "{\\"summary\\":\\"ok\\",\\"primary_evidence\\":[],\\"supporting_evidence\\":[],\\"alternative_explanation\\":\\"none\\",\\"uncertainty\\":\\"low\\",\\"recommended_investigation\\":[]}"}}]}'

    def fake_urlopen(request, timeout):
        captured["body"] = json.loads(request.data)
        captured["timeout"] = timeout
        return Response()

    monkeypatch.setattr("app.ai.providers.llama_cpp.urlopen", fake_urlopen)
    result = LlamaCppHttpProvider(timeout_seconds=4).explain(PACKET)
    assert result.status == "received"
    assert result.evidence_fingerprint == "fp_1"
    assert captured["timeout"] == 4
    assert captured["body"]["max_tokens"] == 768
    assert captured["body"]["response_format"]["type"] == "json_schema"
    assert captured["body"]["response_format"]["json_schema"]["schema"]["additionalProperties"] is False
    assert captured["body"]["response_format"]["json_schema"]["schema"]["properties"]["primary_evidence"]["items"]["properties"]["evidence_id"]["enum"] == []
    assert json.loads(captured["body"]["messages"][1]["content"]) == build_inference_view(PACKET)


def test_provider_enum_contains_only_inference_view_evidence(monkeypatch):
    _allow_provider_request(monkeypatch)
    captured = {}
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self): return b'{"choices": [{"finish_reason": "stop", "message": {"content": "{\\"summary\\":\\"ok\\",\\"primary_evidence\\":[],\\"supporting_evidence\\":[],\\"alternative_explanation\\":\\"none\\",\\"uncertainty\\":\\"low\\",\\"recommended_investigation\\":[]}"}}]}'
    def fake_urlopen(request, timeout):
        captured["body"] = json.loads(request.data)
        return Response()
    monkeypatch.setattr("app.ai.providers.llama_cpp.urlopen", fake_urlopen)
    packet = {"case_id": "case_1", "evidence_fingerprint": "fp_1", "evidence": [{"evidence_id": f"ev_{i}", "source": "rule", "description": "x" * 180} for i in range(100)]}
    assert LlamaCppHttpProvider(timeout_seconds=4).explain(packet).status == "received"
    schema = captured["body"]["response_format"]["json_schema"]["schema"]
    enum_ids = schema["properties"]["primary_evidence"]["items"]["properties"]["evidence_id"]["enum"]
    assert len(enum_ids) == 10
    assert "ev_099" not in enum_ids


def test_provider_maps_timeout_and_malformed_response(monkeypatch):
    _allow_provider_request(monkeypatch)
    monkeypatch.setattr("app.ai.providers.llama_cpp.urlopen", lambda *args, **kwargs: (_ for _ in ()).throw(TimeoutError()))
    assert LlamaCppHttpProvider().explain(PACKET).status == "timeout"

    class BadResponse:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self): return b'{"choices": [{"finish_reason": "stop", "message": {"content": "not-json"}}]}'

    monkeypatch.setattr("app.ai.providers.llama_cpp.urlopen", lambda *args, **kwargs: BadResponse())
    assert LlamaCppHttpProvider().explain(PACKET).status == "invalid_response"


def test_provider_rejects_reasoning_output_for_structured_case_analysis(monkeypatch):
    _allow_provider_request(monkeypatch)
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self):
            return b'{"choices": [{"finish_reason": "stop", "message": {"content": "{\\"summary\\":\\"ok\\"}", "reasoning_content": "hidden reasoning"}}]}'

    monkeypatch.setattr("app.ai.providers.llama_cpp.urlopen", lambda *args, **kwargs: Response())
    result = LlamaCppHttpProvider().explain(PACKET)
    assert result.status == "invalid_response"
    assert "reasoning output" in result.error


def test_provider_rejects_invalid_output_budget():
    with pytest.raises(ValueError, match="max tokens"):
        LlamaCppHttpProvider(max_tokens=0)


def test_system_prompt_matches_evidence_object_schema():
    for field in ("primary_evidence", "supporting_evidence"):
        evidence_schema = ANALYSIS_SCHEMA["properties"][field]["items"]
        assert evidence_schema["type"] == "object"
        assert evidence_schema["required"] == ["evidence_id", "reason"]
        assert evidence_schema["properties"]["reason"]["maxLength"] == 96
        assert build_analysis_schema(["ev_known"])["properties"][field]["items"]["properties"]["reason"]["maxLength"] == 96
    assert "each an array of at most 2 objects" in SYSTEM_PROMPT
    assert "exactly evidence_id" in SYSTEM_PROMPT
    assert "reason (a complete standalone sentence" in SYSTEM_PROMPT
    assert "prefer concise wording" in SYSTEM_PROMPT
    assert "aim for 40–48 characters" in SYSTEM_PROMPT
    assert "never exceed 96 characters" in SYSTEM_PROMPT
    assert "64 characters" not in SYSTEM_PROMPT
    assert "array of existing evidence_id strings" not in SYSTEM_PROMPT


def test_analysis_accepts_complete_reason_ending_in_known():
    analysis = {
        "summary": "Observed behavior warrants review.",
        "primary_evidence": [{"evidence_id": "ev_known", "reason": "ASN is already known"}],
        "supporting_evidence": [],
        "alternative_explanation": "Could be routine network activity.",
        "uncertainty": "moderate",
        "recommended_investigation": [],
    }

    assert _analysis_validation_error(analysis, {"ev_known"}) is None


def test_analysis_accepts_91_character_reason():
    analysis = {
        "summary": "Observed behavior warrants review.",
        "primary_evidence": [{
            "evidence_id": "ev_known",
            "reason": "Rare path activity detected at /xmlrpc.php with 11 requests over 3 days, scoring 67 rarity.",
        }],
        "supporting_evidence": [],
        "alternative_explanation": "Could be routine network activity.",
        "uncertainty": "moderate",
        "recommended_investigation": [],
    }

    assert len(analysis["primary_evidence"][0]["reason"]) == 91
    assert _analysis_validation_error(analysis, {"ev_known"}) is None


@pytest.mark.parametrize(
    ("field_value", "expected_error"),
    [
        (["ev_known"], "primary_evidence[0]: expected object with evidence_id and reason"),
        ([{"evidence_id": "ev_unknown", "reason": "reason"}], "primary_evidence[0].evidence_id: not present in CasePacket evidence"),
        ([{"evidence_id": "ev_known", "reason": 97 * "x"}], "primary_evidence[0].reason: exceeds 96 characters"),
    ],
)
def test_analysis_validation_reports_specific_evidence_error(field_value, expected_error):
    analysis = {
        "summary": "Observed behavior needs review.",
        "primary_evidence": field_value,
        "supporting_evidence": [],
        "alternative_explanation": "Could be a benign scanner.",
        "uncertainty": "moderate",
        "recommended_investigation": [],
    }

    assert _analysis_validation_error(analysis, {"ev_known"}) == expected_error


@pytest.mark.parametrize("reason", ["Evidence indicates activity from", "Repeated probes,"])
def test_analysis_still_rejects_obvious_incomplete_reason_fragments(reason):
    analysis = {
        "summary": "Observed behavior warrants review.",
        "primary_evidence": [{"evidence_id": "ev_known", "reason": reason}],
        "supporting_evidence": [],
        "alternative_explanation": "Could be routine network activity.",
        "uncertainty": "moderate",
        "recommended_investigation": [],
    }

    assert _analysis_validation_error(analysis, {"ev_known"}) == "primary_evidence[0].reason: incomplete text"


def test_provider_returns_field_specific_schema_failure(monkeypatch):
    _allow_provider_request(monkeypatch)
    analysis = {
        "summary": "Observed behavior needs review.",
        "primary_evidence": ["ev_known"],
        "supporting_evidence": [],
        "alternative_explanation": "Could be a benign scanner.",
        "uncertainty": "moderate",
        "recommended_investigation": [],
    }
    payload = {"choices": [{"finish_reason": "stop", "message": {"content": json.dumps(analysis)}}]}

    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self): return json.dumps(payload).encode()

    monkeypatch.setattr("app.ai.providers.llama_cpp.urlopen", lambda *args, **kwargs: Response())
    packet = {**PACKET, "evidence": [{"evidence_id": "ev_known", "description": "Known evidence"}]}

    result = LlamaCppHttpProvider().explain(packet)

    assert result.status == "invalid_response"
    assert result.error == "CaseAnalysis validation failed: primary_evidence[0]: expected object with evidence_id and reason"


def test_analysis_rejects_extra_fields():
    analysis = {
        "summary": "ok",
        "primary_evidence": [],
        "supporting_evidence": [],
        "alternative_explanation": "none",
        "uncertainty": "low",
        "recommended_investigation": [],
        "mitre_mapping": [],
    }
    assert not _valid_analysis(analysis, set())


def test_dynamic_schema_enumerates_packet_ids_and_bounds_zero_evidence():
    schema = build_analysis_schema(["ev_b", "ev_a", "ev_a"])
    evidence = schema["properties"]["primary_evidence"]
    assert evidence["items"]["properties"]["evidence_id"]["enum"] == ["ev_a", "ev_b"]
    assert evidence["maxItems"] == 2
    empty = build_analysis_schema([])
    assert empty["properties"]["primary_evidence"]["maxItems"] == 0
    assert empty["properties"]["supporting_evidence"]["maxItems"] == 0


def test_provider_maps_unavailable_without_retry(monkeypatch):
    _allow_provider_request(monkeypatch)
    calls = []
    def fail(*args, **kwargs):
        calls.append(1)
        raise URLError("offline")
    monkeypatch.setattr("app.ai.providers.llama_cpp.urlopen", fail)
    result = LlamaCppHttpProvider().explain(PACKET)
    assert result.status == "unavailable"
    assert len(calls) == 1


@pytest.mark.parametrize("configured_budget", [None, "not-a-number", "-12", "0"])
def test_runtime_budget_fails_closed_without_http(monkeypatch, configured_budget):
    calls = []
    if configured_budget is None:
        monkeypatch.delenv("LOCAL_REASONING_MAX_INPUT_TOKENS", raising=False)
    else:
        monkeypatch.setenv("LOCAL_REASONING_MAX_INPUT_TOKENS", configured_budget)
    monkeypatch.setattr("app.ai.providers.llama_cpp.estimate_prompt_tokens", lambda *parts: 40)
    monkeypatch.setattr("app.ai.providers.llama_cpp.urlopen", lambda *args, **kwargs: calls.append(1))

    result = LlamaCppHttpProvider().explain(PACKET)

    assert result.status == "abstained"
    assert result.error == "local_reasoning_budget_exceeded"
    assert result.diagnostics["estimated_input_tokens"] == 40
    assert result.diagnostics["configured_input_budget_tokens"] == 0
    assert calls == []


def test_runtime_budget_abstains_above_positive_limit_without_http(monkeypatch):
    calls = []
    monkeypatch.setenv("LOCAL_REASONING_MAX_INPUT_TOKENS", "39")
    monkeypatch.setattr("app.ai.providers.llama_cpp.estimate_prompt_tokens", lambda *parts: 40)
    monkeypatch.setattr("app.ai.providers.llama_cpp.urlopen", lambda *args, **kwargs: calls.append(1))

    result = LlamaCppHttpProvider().explain(PACKET)

    assert result.status == "abstained"
    assert result.diagnostics["configured_input_budget_tokens"] == 39
    assert calls == []


@pytest.mark.parametrize("budget", [40, 41])
def test_runtime_budget_boundary_and_below_use_provider(monkeypatch, budget):
    _allow_provider_request(monkeypatch, str(budget))
    monkeypatch.setattr("app.ai.providers.llama_cpp.estimate_prompt_tokens", lambda *parts: 40)

    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self):
            return b'{"choices": [{"finish_reason": "stop", "message": {"content": "{\\"summary\\":\\"ok\\",\\"primary_evidence\\":[],\\"supporting_evidence\\":[],\\"alternative_explanation\\":\\"none\\",\\"uncertainty\\":\\"low\\",\\"recommended_investigation\\":[]}"}}]}'

    calls = []
    def fake_urlopen(*args, **kwargs):
        calls.append(1)
        return Response()
    monkeypatch.setattr("app.ai.providers.llama_cpp.urlopen", fake_urlopen)

    result = LlamaCppHttpProvider().explain(PACKET)

    assert result.status == "received"
    assert result.diagnostics == {
        "estimated_input_tokens": 40,
        "configured_input_budget_tokens": budget,
        "context_input_limit_tokens": __import__("app.ai.providers.llama_cpp", fromlist=["_configured_context_input_limit"])._configured_context_input_limit(),
    }
    assert len(calls) == 1


def test_context_safety_limit_remains_too_large_not_abstained(monkeypatch):
    import app.ai.providers.llama_cpp as llama_cpp

    _allow_provider_request(monkeypatch, "100")
    monkeypatch.setattr(llama_cpp, "estimate_prompt_tokens", lambda *parts: 51)
    monkeypatch.setenv("FOUNDATION_SEC_CONTEXT_SIZE", "690")
    calls = []
    monkeypatch.setattr(llama_cpp, "urlopen", lambda *args, **kwargs: calls.append(1))

    result = LlamaCppHttpProvider().explain(PACKET)

    assert result.status == "too_large"
    assert result.status != "abstained"
    assert result.diagnostics == {
        "estimated_input_tokens": 51,
        "configured_input_budget_tokens": 100,
        "context_input_limit_tokens": 50,
    }
    assert calls == []


@pytest.mark.parametrize(
    ("outcome", "expected_status"),
    [
        ("received", "received"),
        ("invalid", "invalid_response"),
        ("timeout", "timeout"),
        ("unavailable", "unavailable"),
        ("http_error", "http_error"),
    ],
)
def test_provider_results_include_safe_token_diagnostics(monkeypatch, outcome, expected_status):
    _allow_provider_request(monkeypatch, "100")
    monkeypatch.setattr("app.ai.providers.llama_cpp.estimate_prompt_tokens", lambda *parts: 40)

    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self):
            if outcome == "invalid":
                return b'{"choices": [{"finish_reason": "stop", "message": {"content": "not-json"}}]}'
            return b'{"choices": [{"finish_reason": "stop", "message": {"content": "{\\"summary\\":\\"ok\\",\\"primary_evidence\\":[],\\"supporting_evidence\\":[],\\"alternative_explanation\\":\\"none\\",\\"uncertainty\\":\\"low\\",\\"recommended_investigation\\":[]}"}}]}'

    def fake_urlopen(*args, **kwargs):
        if outcome == "timeout":
            raise TimeoutError()
        if outcome == "unavailable":
            raise URLError("offline")
        if outcome == "http_error":
            raise HTTPError("http://localhost", 503, "unavailable", {}, None)
        return Response()
    monkeypatch.setattr("app.ai.providers.llama_cpp.urlopen", fake_urlopen)

    result = LlamaCppHttpProvider().explain(PACKET)

    assert result.status == expected_status
    assert result.diagnostics["estimated_input_tokens"] == 40
    assert result.diagnostics["configured_input_budget_tokens"] == 100
    assert result.diagnostics["context_input_limit_tokens"] > 40


def test_provider_rejects_case_over_inference_budget_without_http_call(monkeypatch):
    _allow_provider_request(monkeypatch)
    calls = []
    monkeypatch.setattr("app.ai.providers.llama_cpp.urlopen", lambda *args, **kwargs: calls.append(1))
    packet = {
        "case_id": "case_large",
        "evidence_fingerprint": "fp_large",
        "evidence": [{"evidence_id": "ev_1", "description": "x"}],
        "representative_requests": [
            {"method": "GET", "path": f"/{index}-{'x' * 180}", "status": 404}
            for index in range(100)
        ],
    }
    result = LlamaCppHttpProvider(timeout_seconds=4).explain(packet)
    assert result.status == "too_large"
    assert "inference budget" in result.error
    assert calls == []


def test_context_input_limit_uses_safe_fallback_for_missing_or_invalid_config(monkeypatch):
    import app.ai.providers.llama_cpp as llama_cpp

    monkeypatch.delenv("FOUNDATION_SEC_CONTEXT_SIZE", raising=False)
    assert llama_cpp._configured_context_tokens() == 4096
    assert llama_cpp._configured_context_input_limit() == 4096 - 256 - 384

    monkeypatch.setenv("FOUNDATION_SEC_CONTEXT_SIZE", "invalid")
    assert llama_cpp._configured_context_tokens() == 4096
    assert llama_cpp._configured_context_input_limit() == 4096 - 256 - 384


def test_context_setting_loaded_after_provider_import_is_used_by_explain():
    source = r'''import json, os
from app.ai.providers import llama_cpp
imported_limit = llama_cpp.MAX_INPUT_TOKENS
os.environ["FOUNDATION_SEC_CONTEXT_SIZE"] = "8192"
os.environ["LOCAL_REASONING_MAX_INPUT_TOKENS"] = "6000"
llama_cpp.estimate_prompt_tokens = lambda *parts: 5000
llama_cpp.urlopen = lambda *args, **kwargs: (_ for _ in ()).throw(TimeoutError())
result = llama_cpp.LlamaCppHttpProvider().explain({"case_id": "case", "evidence_fingerprint": "fp"})
print(json.dumps({"status": result.status, "imported_limit": imported_limit,
                  "context_limit": result.diagnostics["context_input_limit_tokens"]}))
'''
    child_env = os.environ.copy()
    child_env.pop("FOUNDATION_SEC_CONTEXT_SIZE", None)
    child_env.pop("LOCAL_REASONING_MAX_TOKENS", None)

    completed = subprocess.run(
        [sys.executable, "-c", source],
        check=True,
        capture_output=True,
        text=True,
        env=child_env,
    )
    result = json.loads(completed.stdout)

    assert result == {
        "status": "timeout",
        "imported_limit": 4096 - 256 - 384,
        "context_limit": 8192 - 256 - 384,
    }
