import os

import pytest

from app.ai.providers.llama_cpp import LlamaCppHttpProvider


PACKETS = [
    {"case_id": "case_benign", "evidence_fingerprint": "fp_benign", "subject": {"ip": "203.0.113.1"}, "classification": {"label": "good", "risk_score": 2}},
    {"case_id": "case_medium", "evidence_fingerprint": "fp_medium", "subject": {"ip": "203.0.113.2"}, "classification": {"label": "medium", "risk_score": 42}, "evidence": [{"evidence_id": "ev_rule", "type": "rule"}]},
    {"case_id": "case_rare", "evidence_fingerprint": "fp_rare", "subject": {"ip": "203.0.113.3"}, "classification": {"label": "medium", "risk_score": 35}, "evidence": [{"evidence_id": "ev_rare", "type": "rare_path"}]},
    {"case_id": "case_if", "evidence_fingerprint": "fp_if", "subject": {"ip": "203.0.113.4"}, "classification": {"label": "medium", "risk_score": 38}, "evidence": [{"evidence_id": "ev_if", "type": "isolation_forest"}]},
    {"case_id": "case_mixed", "evidence_fingerprint": "fp_mixed", "subject": {"ip": "203.0.113.5"}, "classification": {"label": "critical", "risk_score": 85}, "evidence": [{"evidence_id": "ev_rule", "type": "rule"}, {"evidence_id": "ev_privacy", "type": "privacy"}]},
]


@pytest.mark.integration
def test_foundation_sec_acceptance_smoke():
    endpoint = os.getenv("LOCAL_REASONING_BASE_URL")
    if not endpoint or not os.getenv("FOUNDATION_SEC_MODEL_PATH"):
        pytest.skip("Set local reasoning endpoint and Foundation-Sec model path")
    provider = LlamaCppHttpProvider(endpoint, os.getenv("FOUNDATION_SEC_MODEL_NAME", "Foundation-Sec-8B-Reasoning"), float(os.getenv("LOCAL_REASONING_TIMEOUT_SECONDS", "30")))
    for packet in PACKETS:
        result = provider.explain(packet)
        assert result.status == "received"
        assert result.evidence_fingerprint == packet["evidence_fingerprint"]
        assert isinstance(result.raw_response, dict)
