from app.ai.reasoning import ReasoningResult
from app.services.ai_explain_worker import AiExplainWorker


PACKET = {"case_id": "case_1", "evidence_fingerprint": "fp_1", "evidence": [{"evidence_id": "ev_1"}]}
VALID = '{"summary":"scan","primary_evidence":[{"evidence_id":"ev_1","reason":"rule"}],"supporting_evidence":[],"alternative_explanation":"none","uncertainty":"moderate","recommended_investigation":[]}'


class Repo:
    def __init__(self): self.job = {"job_id": "job_1", "case_id": "case_1", "evidence_fingerprint": "fp_1"}; self.completed = None; self.failed = None
    def claim_pending(self): job, self.job = self.job, None; return job
    def persist_completed(self, job_id, analysis, validation, provenance): self.completed = (job_id, analysis, validation, provenance); return {"status": "completed"}
    def persist_failed(self, job_id, failure_code, validation_status, provider_status, provenance): self.failed = (job_id, failure_code, validation_status, provider_status, provenance); return {"status": "failed"}


class Provider:
    def __init__(self, result): self.result = result; self.calls = 0
    def explain(self, packet): self.calls += 1; return self.result


def test_worker_completes_only_grounded_analysis():
    repo, provider = Repo(), Provider(ReasoningResult("received", "fp_1", {"choices": [{"finish_reason": "stop", "message": {"content": VALID}}]}))
    worker = AiExplainWorker(repo, provider, {"case_1": PACKET}.get, provenance={"run": "test"})
    assert worker.run_once() is True
    assert provider.calls == 1 and repo.completed[0] == "job_1" and repo.failed is None


def test_worker_maps_timeout_without_retry():
    repo, provider = Repo(), Provider(ReasoningResult("timeout", "fp_1", error="timeout"))
    worker = AiExplainWorker(repo, provider, {"case_1": PACKET}.get)
    worker.run_once()
    assert repo.failed[2:4] == ("timeout", "timeout")
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
