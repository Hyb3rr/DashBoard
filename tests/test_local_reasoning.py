import json
from urllib.error import URLError

import pytest

from app.ai.providers.llama_cpp import LlamaCppHttpProvider, build_analysis_schema
from app.ai.inference_view import build_inference_view


PACKET = {"case_id": "case_1", "evidence_fingerprint": "fp_1", "subject": {"ip": "203.0.113.10"}}


def test_provider_rejects_non_local_endpoint():
    with pytest.raises(ValueError, match="localhost HTTP"):
        LlamaCppHttpProvider("http://example.com/v1/chat/completions")


def test_provider_posts_structured_untrusted_packet(monkeypatch):
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
    assert captured["body"]["max_tokens"] == 256
    assert captured["body"]["response_format"]["type"] == "json_schema"
    assert captured["body"]["response_format"]["json_schema"]["schema"]["additionalProperties"] is False
    assert captured["body"]["response_format"]["json_schema"]["schema"]["properties"]["primary_evidence"]["items"]["properties"]["evidence_id"]["enum"] == []
    assert json.loads(captured["body"]["messages"][1]["content"]) == build_inference_view(PACKET)


def test_provider_enum_contains_only_inference_view_evidence(monkeypatch):
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
    monkeypatch.setattr("app.ai.providers.llama_cpp.urlopen", lambda *args, **kwargs: (_ for _ in ()).throw(TimeoutError()))
    assert LlamaCppHttpProvider().explain(PACKET).status == "timeout"

    class BadResponse:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self): return b'{"choices": [{"finish_reason": "stop", "message": {"content": "not-json"}}]}'

    monkeypatch.setattr("app.ai.providers.llama_cpp.urlopen", lambda *args, **kwargs: BadResponse())
    assert LlamaCppHttpProvider().explain(PACKET).status == "invalid_response"


def test_provider_rejects_invalid_output_budget():
    with pytest.raises(ValueError, match="max tokens"):
        LlamaCppHttpProvider(max_tokens=0)


def test_dynamic_schema_enumerates_packet_ids_and_bounds_zero_evidence():
    schema = build_analysis_schema(["ev_b", "ev_a", "ev_a"])
    evidence = schema["properties"]["primary_evidence"]
    assert evidence["items"]["properties"]["evidence_id"]["enum"] == ["ev_a", "ev_b"]
    assert evidence["maxItems"] == 2
    empty = build_analysis_schema([])
    assert empty["properties"]["primary_evidence"]["maxItems"] == 0
    assert empty["properties"]["supporting_evidence"]["maxItems"] == 0


def test_provider_maps_unavailable_without_retry(monkeypatch):
    calls = []
    def fail(*args, **kwargs):
        calls.append(1)
        raise URLError("offline")
    monkeypatch.setattr("app.ai.providers.llama_cpp.urlopen", fail)
    result = LlamaCppHttpProvider().explain(PACKET)
    assert result.status == "unavailable"
    assert len(calls) == 1


def test_provider_rejects_case_over_inference_budget_without_http_call(monkeypatch):
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
