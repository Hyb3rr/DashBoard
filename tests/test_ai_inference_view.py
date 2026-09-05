import json
from copy import deepcopy

from app.ai.inference_view import INFERENCE_VIEW_CONFIG, build_inference_view


def test_view_is_deterministic_bounded_and_preserves_canonical_packet():
    packet = {
        "case_id": "case_1",
        "evidence_fingerprint": "fp_1",
        "classification": {"label": "medium", "risk_score": 42},
        "traffic_summary": {"requests": 20, "unique_paths": 2, "status_4xx_ratio": 0.8},
        "evidence": [{"evidence_id": "ev_a"}],
        "representative_requests": [
            {"method": "GET", "path": "/scan", "status": 404},
            {"method": "GET", "path": "/scan", "status": 404},
            {"method": "POST", "path": "/login", "status": 401},
        ],
    }
    original = deepcopy(packet)
    view = build_inference_view(packet)

    assert packet == original
    assert view["case_id"] == packet["case_id"]
    assert view["evidence_fingerprint"] == packet["evidence_fingerprint"]
    assert view["classification"] == packet["classification"]
    assert view["evidence"] == packet["evidence"]
    assert view["request_patterns"][0]["count"] == 2
    assert "representative_requests" not in view
    assert len(view["request_patterns"]) <= 20
    assert len(view.get("representative_examples", [])) <= INFERENCE_VIEW_CONFIG["max_representative_examples"]
    assert build_inference_view(packet) == view


def test_view_handles_zero_requests_without_sentinel_or_loss():
    packet = {"evidence": [], "representative_requests": []}
    view = build_inference_view(packet)
    assert view == packet


def test_view_keeps_patterns_and_drops_optional_examples_over_budget():
    packet = {"representative_requests": [{"method": "GET", "path": f"/{i}-{'x' * 150}", "status": 404} for i in range(20)]}
    view = build_inference_view(packet)
    assert len(view["request_patterns"]) == 20
    assert view["request_context"]["pattern_count"] == 20
    assert "representative_examples" not in view
    assert len(json.dumps(view, ensure_ascii=False, sort_keys=True)) > INFERENCE_VIEW_CONFIG["max_input_chars"]


def test_view_selects_bounded_evidence_without_mutating_canonical_packet():
    packet = {
        "evidence": [{"evidence_id": f"ev_{i:03d}", "source": "rule", "description": "x" * 180} for i in range(100)],
        "representative_requests": [],
    }
    view = build_inference_view(packet)
    assert len(packet["evidence"]) == 100
    assert view["evidence_context"] == {"evidence_total": 100, "evidence_included": 10, "evidence_omitted": 90}
    assert len(view["evidence"]) == 10
    assert len({item["evidence_id"] for item in view["evidence"]}) == 10
    assert build_inference_view(packet) == view


def test_view_prioritizes_security_evidence_and_reports_omitted_ids():
    packet = {"evidence": [
        {"evidence_id": "ev_geo", "source": "geo_context", "description": "geo"},
        {"evidence_id": "ev_rare", "source": "rare_path", "description": "rare"},
        {"evidence_id": "ev_rule", "source": "rule", "description": "rule"},
    ]}
    view = build_inference_view(packet)
    assert [item["evidence_id"] for item in view["evidence"]] == ["ev_rule", "ev_rare", "ev_geo"]
    assert view["evidence_context"]["evidence_omitted"] == 0
