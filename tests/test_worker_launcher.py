import sys


def test_launcher_loads_env_defaults_and_passes_endpoint(monkeypatch, tmp_path):
    from scripts.ai import run_explain_worker

    captured = {}
    class FakeWorker:
        def __init__(self, repo, provider, loader, **kwargs):
            captured.update(provider=provider, kwargs=kwargs)
        def run_once(self): pass
        def stop(self): pass

    class FakeProvider:
        def __init__(self, endpoint, model, timeout):
            captured.update(endpoint=endpoint, model=model, timeout=timeout)

    monkeypatch.setattr(run_explain_worker, "AiExplainWorker", FakeWorker)
    monkeypatch.setattr(run_explain_worker, "LlamaCppHttpProvider", FakeProvider)
    monkeypatch.setattr(run_explain_worker, "_load_packets", lambda _: {})
    monkeypatch.setattr(run_explain_worker, "load_dotenv", lambda: None)
    monkeypatch.setenv("LOCAL_REASONING_PORT", "18081")
    monkeypatch.setenv("FOUNDATION_SEC_MODEL_NAME", "local-foundation")
    monkeypatch.setenv("LOCAL_REASONING_TIMEOUT_SECONDS", "90")
    monkeypatch.setattr(sys, "argv", ["worker", "--packets", str(tmp_path / "packets.json"), "--once"])

    assert run_explain_worker.main() == 0
    assert captured["endpoint"] == "http://127.0.0.1:18081/v1/chat/completions"
    assert captured["model"] == "local-foundation"
    assert captured["timeout"] == 90.0


def test_endpoint_base_url_gets_completion_path(monkeypatch):
    from scripts.ai.run_explain_worker import _endpoint_default
    monkeypatch.setenv("LOCAL_REASONING_BASE_URL", "http://127.0.0.1:18081")
    monkeypatch.delenv("LOCAL_REASONING_ENDPOINT", raising=False)
    assert _endpoint_default() == "http://127.0.0.1:18081/v1/chat/completions"
