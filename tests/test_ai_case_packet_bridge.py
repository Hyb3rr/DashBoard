from datetime import datetime, timezone

from app.routers import ai_explanations
from app.services.case_packets import build_live_case_packet


def test_live_packet_is_bounded_and_stable():
    snapshot = {
        "classification": {"label": "medium", "score": 42, "confidence": 80, "evidence": ["sensitive path"]},
        "observation": {"requests": 3, "unique_paths": 2, "status_4xx": 2, "rare_path_evidence": []},
    }
    traffic = {"total_requests": 3, "recent_requests": [{"method": "GET", "path": "/.env", "status": 404}]}
    packet_a = build_live_case_packet("203.0.113.10", snapshot, traffic, "start", "end")
    packet_b = build_live_case_packet("203.0.113.10", snapshot, traffic, "start", "end")
    assert packet_a == packet_b
    assert packet_a["classification"]["label"] == "medium"
    assert packet_a["evidence_fingerprint"] == packet_b["evidence_fingerprint"]
    assert len(packet_a["representative_requests"]) <= 20


def test_ip_request_builds_packet_and_persists_snapshot(monkeypatch):
    calls = {}
    class FakeState:
        def get(self, ip):
            assert ip == "203.0.113.10"
            return {"ip": ip, "observation_payload": {"requests": 1, "unique_paths": 1, "status_4xx": 1}}
    monkeypatch.setattr(ai_explanations, "StateRepository", FakeState)
    monkeypatch.setattr(ai_explanations, "_pg_item", lambda row: {"classification": {"label": "good", "score": 5}, "observation": row["observation_payload"]})
    monkeypatch.setattr(ai_explanations.clickhouse_store, "traffic_for_ip", lambda *args: {"total_requests": 1, "recent_requests": []})
    class FakeRepo:
        def create_or_get(self, case_id, fingerprint, case_packet=None):
            calls.update(case_id=case_id, fingerprint=fingerprint, packet=case_packet)
            return {"job_id": "job_1", "case_id": case_id, "evidence_fingerprint": fingerprint, "status": "pending"}
    monkeypatch.setattr(ai_explanations, "AiExplainJobRepository", FakeRepo)
    result = ai_explanations.request_explanation("203.0.113.10", ai_explanations.ExplainRequest())
    assert result["status"] == "pending"
    assert calls["packet"]["case_id"] == calls["case_id"]
    assert calls["packet"]["evidence_fingerprint"] == calls["fingerprint"]


def test_worker_prefers_persisted_packet(monkeypatch):
    from app.services.ai_explain_worker import AiExplainWorker
    class Repo:
        def claim_pending(self): return {"job_id": "j", "case_id": "unused", "evidence_fingerprint": "fp", "case_packet_json": {"evidence_fingerprint": "fp"}}
        def persist_completed(self, *args): return {}
        def persist_failed(self, *args): raise AssertionError(args)
    class Provider:
        def explain(self, packet):
            return type("R", (), {"status": "received", "error": None})()
    monkeypatch.setattr("app.services.ai_explain_worker.evaluate_case", lambda *args, **kwargs: {"grounded": True, "analysis": {"summary": "ok"}, "validation": {"grounded": True}, "unsupported_evidence_ids": []})
    worker = AiExplainWorker(Repo(), Provider(), lambda _: (_ for _ in ()).throw(AssertionError("loader used")))
    assert worker.run_once() is True
