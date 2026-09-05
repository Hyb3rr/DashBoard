from datetime import datetime

import pytest

from app.core.evidence import UnifiedEvidence
from app.core.enrichment import build_enrichment_evidence
from app.core.rules import Detection
from app.services.rare_path_detector import build_rare_path_evidence


def test_evidence_id_is_stable_across_mapping_order_and_freshness():
    values = dict(source="rule", type="rule", severity="high", baseline={"threshold": 1}, score_contribution=8, observed_at="2026-09-03T00:00:00+00:00", description="matched rule")
    first = UnifiedEvidence(observed={"b": 2, "a": 1}, freshness="old", **values)
    second = UnifiedEvidence(observed={"a": 1, "b": 2}, freshness="new", **values)
    assert first.evidence_id == second.evidence_id


def test_rule_adapter_preserves_rule_version_and_score():
    evidence = Detection("WEB-SCAN-001", "scan", "high", "T1595", 12, "scan matched", 3, "technique").to_evidence("2026-09-03T00:00:00+00:00")
    payload = evidence.to_dict()
    assert payload["source"] == "rule"
    assert payload["observed"]["rule_id"] == "WEB-SCAN-001"
    assert payload["baseline"]["rule_version"] == 3
    assert payload["score_contribution"] == 12


def test_rare_path_adapter_marks_shadow_evidence_supporting_only():
    payload = build_rare_path_evidence({"path": "/.env", "path_requests": 2, "path_ips": 1, "total_ips": 100, "temporal_buckets": 1, "first_seen": "2026-09-03T00:00:00+00:00", "last_seen": "2026-09-03T00:10:00+00:00"}, datetime.fromisoformat("2026-09-03T00:20:00+00:00"))
    assert payload["source"] == "rare_path_detector"
    assert payload["type"] == "rare_path"
    assert payload["severity"] == "supporting"
    assert payload["score_contribution"] == 0
    assert payload["mode"] == "shadow"


def test_evidence_rejects_tampered_id():
    with pytest.raises(ValueError, match="evidence_id does not match evidence content"):
        UnifiedEvidence(source="rule", type="rule", severity="low", observed={}, baseline={}, score_contribution=0, observed_at="2026-09-03T00:00:00+00:00", description="test", evidence_id="ev_tampered")


def test_enrichment_adapter_emits_separate_supporting_context_types():
    evidence = build_enrichment_evidence({
        "is_vpn": True, "country_code": "VN", "asn": "AS64500",
        "abuse_reputation": {"state": "recent"}, "fetched_at": "2026-09-03T00:00:00+00:00",
    })
    assert [item["type"] for item in evidence] == ["privacy", "reputation", "geo_network"]
    assert all(item["severity"] == "supporting" for item in evidence)
    assert all(item["score_contribution"] == 0 for item in evidence)
