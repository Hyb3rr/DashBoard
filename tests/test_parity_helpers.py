from app.db.parity import normalize_state, semantic_diff
import pytest

pytestmark = pytest.mark.parity


def test_parity_ignores_storage_timestamps_and_ids():
    """Ignore persistence-only metadata when comparing equivalent IP state."""
    left = {
        "observation": {"requests": 3, "behavior_score": 15, "detections_24h": [{"id": "WEB-X"}]},
        "classification": {"label": "good", "score": 15, "confidence": 80},
        "updated_at": "old",
        "seq": 1,
    }
    right = {
        "observation_payload": {"requests": 3, "behavior_score": 15, "detections_24h": [{"id": "WEB-X"}]},
        "label": "good", "classification_score": 15, "classification_confidence": 80,
        "updated_at": "new", "seq": 200,
    }
    assert semantic_diff(left, right) == {}
    assert normalize_state(left)["requests"] == 3


def test_normalize_state_preserves_aliases_and_observation_precedence():
    """Prefer observation values while mapping detector-specific count aliases."""
    state = normalize_state({
        "observation": {
            "requests": 4,
            "sensitive_probe_requests": 2,
            "wp_login_requests": 3,
            "bot_requests": 5,
        },
        "requests": 99,
        "sensitive_hits": 8,
        "wp_login_hits": 9,
        "bot_hits": 10,
    })

    assert state["requests"] == 4
    assert state["sensitive_hits"] == 2
    assert state["wp_login_hits"] == 3
    assert state["bot_hits"] == 5
