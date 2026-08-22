from app.db.parity import normalize_state, semantic_diff
import pytest

pytestmark = pytest.mark.parity


def test_parity_ignores_storage_timestamps_and_ids():
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
