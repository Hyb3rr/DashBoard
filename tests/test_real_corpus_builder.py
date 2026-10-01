from datetime import datetime, timezone

from app.core.classification_provenance import classification_input_provenance
from app.db import state_repository
from app.db.repositories import StateRepository
from scripts.ai.build_real_corpus import build_corpus


SNAPSHOT = datetime(2026, 9, 3, tzinfo=timezone.utc)


def traffic(*args):
    return {"total_requests": 10, "status_codes": {"4xx": 8}, "top_paths": [{"path": "/wp-login.php"}], "recent_requests": [{"method": "GET", "path": "/wp-login.php", "status": 404}]}


def row(ip="203.0.113.10"):
    return {"identity_ip": ip, "label": "medium", "classification_score": 42, "classification_confidence": 80, "observation_payload": {"requests": 10, "status_4xx": 8, "detections_24h": [{"id": "WEB-4XX-001", "name": "Repeated client errors", "points": 15, "evidence": "4xx ratio above 50 percent", "severity": "medium"}]}}


def test_builder_is_deterministic_and_bounded():
    first = build_corpus([row()], traffic, SNAPSHOT)
    second = build_corpus([row()], traffic, SNAPSHOT)
    assert first == second
    assert first["manifest"]["packet_count"] == 1
    assert first["manifest"]["selection_reason"]["203.0.113.10"] == ["classification_medium", "rule_fired", "high_404"]
    assert first["cases"][0]["evidence"][0]["type"] == "rule"
    assert first["manifest"]["builder_version"] == "ai-3b0-v3"
    assert list(first["score_comparison_snapshots"]) == [first["cases"][0]["case_id"]]


def test_builder_does_not_assign_ground_truth_or_call_ai():
    packet = build_corpus([row("203.0.113.11")], traffic, SNAPSHOT)["cases"][0]
    assert packet["classification"]["label"] == "medium"
    assert "ground_truth" not in packet
    assert "raw_headers" not in packet
    assert "user_agent" not in packet


def test_builder_keeps_stable_ip_tie_break_and_hard_packet_cap():
    rows = [row(f"203.0.113.{index}") for index in range(1, 32)]
    queried_ips = []

    def recording_traffic(_start, _end, _bucket, ip, _dataset):
        queried_ips.append(ip)
        return traffic()

    corpus = build_corpus(rows, recording_traffic, SNAPSHOT, limit=100)

    assert corpus["manifest"]["packet_count"] == 30
    assert queried_ips == sorted(record["identity_ip"] for record in rows)[:30]


def test_comparison_sidecar_captures_selected_v1_inputs_without_changing_casepacket():
    source = row("203.0.113.12")
    source.update({
        "is_tor": False,
        "is_proxy": True,
        "is_vpn": False,
        "is_hosting": False,
        "organization": "Example Network",
        "organization_confidence": 82,
    })
    source["observation_payload"].update({
        "detections_recent": [{"id": "WEB-RATE-001", "points": 12}],
        "detections_1h": [{"id": "WEB-RATE-001", "points": 12}],
        "detections_24h": [{"id": "WEB-4XX-001", "points": 15}],
        "recent_behavior_score": 12,
        "recent_requests": 25,
        "recent_sensitive_probe_requests": 0,
        "recent_behavior_evidence": [{"rule_id": "WEB-RATE-001"}],
        "evaluated_at": "2026-09-03T00:00:00+00:00",
        "ruleset_hash": "combined-rules",
        "ruleset_hash_1h": "one-hour-rules",
        "ruleset_hash_24h": "day-rules",
    })

    corpus = build_corpus([source], traffic, SNAPSHOT, classifier_capture_fingerprint="abc123")
    packet = corpus["cases"][0]
    sidecar = corpus["score_comparison_snapshots"][packet["case_id"]]

    assert set(packet) == {
        "case_id", "evidence_fingerprint", "subject", "classification", "window",
        "traffic_summary", "evidence", "representative_requests",
    }
    assert sidecar["behavior"]["selected_detections"] == [{"id": "WEB-RATE-001", "points": 12}]
    assert sidecar["behavior"]["selected_detections"] != source["observation_payload"]["detections_24h"]
    assert sidecar["behavior"]["selected_detections_available"] is True
    assert sidecar["behavior"]["score"] == 12
    assert sidecar["network_context"] == {"is_tor": False, "is_proxy": True, "is_vpn": False, "is_hosting": False}
    assert sidecar["trust_reduction"] == {
        "organization": "Example Network",
        "organization_confidence": 82,
        "is_hosting": False,
        "behavior_score": 12,
    }
    assert sidecar["persisted_v1"]["classifier_version"] is None
    assert sidecar["persisted_v1"]["classifier_version_status"] == "not_stored_by_classification_persistence"
    assert sidecar["scorer_provenance"]["capture_classifier_fingerprint"] == "abc123"
    assert corpus["manifest"]["score_comparison_sha256"]


def test_comparison_sidecar_preserves_missing_selected_detection_state():
    source = row("203.0.113.13")
    source["observation_payload"].pop("detections_recent", None)

    corpus = build_corpus([source], traffic, SNAPSHOT)
    sidecar = corpus["score_comparison_snapshots"][corpus["cases"][0]["case_id"]]

    assert sidecar["behavior"]["selected_detections_available"] is False
    assert sidecar["behavior"]["selected_detections"] is None
    assert sidecar["behavior"]["selected_detections_missing_reason"] == "detections_recent_not_persisted"


def test_comparison_sidecar_reconstructs_and_preserves_persisted_input_fingerprint():
    source = row("203.0.113.14")
    source.update({
        "country_code": "US",
        "is_proxy": True,
        "organization": "Example Network",
        "organization_confidence": 85,
        "core_enrichment_status": "complete",
        "privacy_enrichment_status": "complete",
    })
    source["observation_payload"].update({
        "recent_behavior_score": 12,
        "recent_requests": 10,
        "recent_sensitive_probe_requests": 0,
        "recent_behavior_evidence": ["rate signal"],
        "rule_coverage": True,
    })
    captured = classification_input_provenance(source, source["observation_payload"], {}, None)
    source["persisted_input_contract_version"] = captured["version"]
    source["persisted_input_fingerprint"] = captured["fingerprint"]

    corpus = build_corpus([source], traffic, SNAPSHOT)
    packet = corpus["cases"][0]
    sidecar = corpus["score_comparison_snapshots"][packet["case_id"]]

    assert sidecar["persisted_v1"]["input_contract_version"] == captured["version"]
    assert sidecar["persisted_v1"]["input_fingerprint"] == captured["fingerprint"]
    assert sidecar["input_fingerprint_reconstruction"] == {
        "contract_version": captured["version"],
        "fingerprint": captured["fingerprint"],
        "canonical_inputs": captured["canonical_inputs"],
    }


def test_inventory_page_includes_input_provenance_only_when_requested(monkeypatch):
    from contextlib import contextmanager

    class Result:
        def __init__(self, row=None, rows=None):
            self.row = row or {}
            self.rows = rows or []

        def fetchone(self):
            return self.row

        def fetchall(self):
            return self.rows

    class Connection:
        def __init__(self):
            self.page_queries = []

        def execute(self, sql, args=()):
            if "SELECT COUNT(*) AS n" in sql:
                return Result({"n": 0})
            if "page_keys AS MATERIALIZED" in sql:
                self.page_queries.append(sql)
                return Result(rows=[])
            return Result({"seq": 0})

    connection = Connection()

    @contextmanager
    def fake_transaction():
        yield connection

    monkeypatch.setattr(state_repository, "transaction", fake_transaction)
    repository = StateRepository()
    repository.page(1, 10, "threat_signal_score", "desc")
    repository.page(1, 10, "threat_signal_score", "desc", include_classification_provenance=True)

    assert "persisted_input_fingerprint" not in connection.page_queries[0]
    assert "cs.input_contract_version AS persisted_input_contract_version" in connection.page_queries[1]
    assert "cs.input_fingerprint AS persisted_input_fingerprint" in connection.page_queries[1]
