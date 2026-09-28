from app.ai.reasoning import ReasoningResult
from app.services.ai_explain_worker import AiExplainWorker


PACKET = {"case_id": "case_1", "evidence_fingerprint": "fp_1", "evidence": [{"evidence_id": "ev_1"}]}
VALID = '{"summary":"scan","primary_evidence":[{"evidence_id":"ev_1","reason":"rule"}],"supporting_evidence":[],"alternative_explanation":"none","uncertainty":"moderate","recommended_investigation":[]}'


class Repo:
    def __init__(self): self.job = {"job_id": "job_1", "case_id": "case_1", "evidence_fingerprint": "fp_1"}; self.completed = None; self.failed = None; self.abstained = None
    def claim_pending(self): job, self.job = self.job, None; return job
    def persist_completed(self, job_id, analysis, validation, provenance): self.completed = (job_id, analysis, validation, provenance); return {"status": "completed"}
    def persist_failed(self, job_id, failure_code, validation_status, provider_status, provenance): self.failed = (job_id, failure_code, validation_status, provider_status, provenance); return {"status": "failed"}
    def persist_abstained(self, job_id, reason, provenance): self.abstained = (job_id, reason, provenance); return {"status": "abstained"}


class Provider:
    def __init__(self, result): self.result = result; self.calls = 0
    def explain(self, packet): self.calls += 1; return self.result


def test_worker_completes_only_grounded_analysis():
    repo, provider = Repo(), Provider(ReasoningResult("received", "fp_1", {"choices": [{"finish_reason": "stop", "message": {"content": VALID}}]}))
    worker = AiExplainWorker(repo, provider, {"case_1": PACKET}.get, provenance={"run": "test", "provider": "llama_cpp", "model": "test-model", "configured_timeout_seconds": 30, "prompt_schema_version": "case-analysis-v1"})
    assert worker.run_once() is True
    assert provider.calls == 1 and repo.completed[0] == "job_1" and repo.failed is None
    provenance = repo.completed[3]
    assert {"provider", "model", "configured_timeout_seconds", "prompt_schema_version", "evidence_fingerprint", "latency_ms"} <= provenance.keys()


def test_worker_maps_timeout_without_retry():
    repo, provider = Repo(), Provider(ReasoningResult("timeout", "fp_1", error="timeout"))
    worker = AiExplainWorker(repo, provider, {"case_1": PACKET}.get)
    worker.run_once()
    assert repo.failed[2:4] == ("timeout", "timeout")
    assert provider.calls == 1


def test_worker_persists_budget_abstention_without_evaluation_or_failure(monkeypatch):
    import app.services.ai_explain_worker as worker_module

    monkeypatch.setattr(worker_module, "evaluate_case", lambda *args, **kwargs: pytest.fail("abstention must not be evaluated"))
    diagnostics = {
        "estimated_input_tokens": 321,
        "configured_input_budget_tokens": 0,
        "context_input_limit_tokens": 7552,
        "raw_response": "must not be copied",
        "prompt": "must not be copied",
    }
    repo = Repo()
    provider = Provider(ReasoningResult("abstained", "fp_1", diagnostics=diagnostics))
    worker = AiExplainWorker(repo, provider, {"case_1": PACKET}.get)

    assert worker.run_once() is True

    assert repo.abstained is not None
    assert repo.abstained[0:2] == ("job_1", "local_reasoning_budget_exceeded")
    assert repo.failed is None and repo.completed is None
    assert provider.calls == 1
    provenance = repo.abstained[2]
    assert provenance["estimated_input_tokens"] == 321
    assert provenance["configured_input_budget_tokens"] == 0
    assert provenance["context_input_limit_tokens"] == 7552
    assert "raw_response" not in provenance and "prompt" not in provenance


def test_abstention_is_neutral_to_provider_backoff_state():
    repo = Repo()
    provider = Provider(ReasoningResult("abstained", "fp_1"))
    worker = AiExplainWorker(repo, provider, {"case_1": PACKET}.get)
    worker._consecutive_provider_failures = 2
    worker._provider_backoff_until = 12345.0

    worker.run_once()

    assert worker._consecutive_provider_failures == 2
    assert worker._provider_backoff_until == 12345.0
    assert repo.failed is None and repo.completed is None
    assert provider.calls == 1


def test_worker_rejects_packet_fingerprint_mismatch():
    repo, provider = Repo(), Provider(ReasoningResult("received"))
    worker = AiExplainWorker(repo, provider, lambda _: {**PACKET, "evidence_fingerprint": "other"})
    worker.run_once()
    assert provider.calls == 0 and repo.failed[2] == "invalid"


def test_worker_stop_prevents_new_claim():
    repo = Repo(); worker = AiExplainWorker(repo, Provider(ReasoningResult("timeout")), {"case_1": PACKET}.get)
    worker.stop()
    assert worker._stop is True


def test_worker_fails_loader_error_without_provider_call():
    repo, provider = Repo(), Provider(ReasoningResult("timeout"))
    def broken_loader(_):
        raise OSError("read model unavailable")
    worker = AiExplainWorker(repo, provider, broken_loader)
    worker.run_once()
    assert provider.calls == 0 and repo.failed[2:4] == ("unavailable", "unavailable")


def test_worker_recovers_stale_jobs_before_polling():
    class RecoveringRepo(Repo):
        def __init__(self):
            super().__init__()
            self.recovered = []
        def recover_stale_running(self, seconds): self.recovered.append(seconds); return 1
        def claim_pending(self): return None

    sleeps = []
    repo = RecoveringRepo()
    worker = AiExplainWorker(repo, Provider(ReasoningResult("timeout")), {}, sleep=lambda seconds: (sleeps.append(seconds), worker.stop()), stale_after_seconds=10)
    worker.run_forever()
    assert repo.recovered == [10]
    assert sleeps == [1.0]


def test_worker_database_error_is_bounded_and_does_not_escape():
    class BrokenRepo:
        def recover_stale_running(self, _): raise RuntimeError("db down")
        def claim_pending(self): raise RuntimeError("db down")
    sleeps = []
    worker = AiExplainWorker(BrokenRepo(), Provider(ReasoningResult("timeout")), {}, sleep=lambda seconds: (sleeps.append(seconds), worker.stop()), stale_after_seconds=1)
    worker.run_forever()
    assert sleeps == [1.0]


def test_worker_backs_off_after_repeated_provider_failures():
    class OneJobRepo(Repo):
        pass

    sleeps = []
    repo = OneJobRepo()
    worker = AiExplainWorker(
        repo,
        Provider(ReasoningResult("timeout", "fp_1", error="timeout")),
        {"case_1": PACKET}.get,
        sleep=lambda seconds: (sleeps.append(seconds), worker.stop()),
        stale_after_seconds=1000,
        provider_failure_threshold=1,
        provider_failure_backoff_seconds=7,
    )
    worker.run_forever()
    assert sleeps and sleeps[0] >= 6.9
