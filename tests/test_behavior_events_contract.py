from datetime import datetime, timezone

import pytest

from app.core.behavior_events import normalize_behavior_event


def event(**overrides):
    value = {
        "event_id": "01JTEST00000000000000000000",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "visitor_id": "visitor-1",
        "session_id": "session-1",
        "event_name": "page_view",
        "path": "/pricing",
        "engagement_ms": None,
        "key_event_name": None,
    }
    value.update(overrides)
    return value


def test_accepts_explicit_page_view_identity_and_nullable_evidence():
    result = normalize_behavior_event(event())
    assert result["visitor_id"] == "visitor-1"
    assert result["session_id"] == "session-1"
    assert result["engagement_ms"] is None
    assert result["key_event_name"] is None


def test_accepts_engagement_and_key_event_payloads():
    assert normalize_behavior_event(event(event_name="engagement", engagement_ms=1250))["engagement_ms"] == 1250.0
    result = normalize_behavior_event(event(event_name="key_event", key_event_name="signup"))
    assert result["key_event_name"] == "signup"


@pytest.mark.parametrize("field", ["visitor_id", "session_id"])
def test_identity_is_required_and_never_inferred(field):
    payload = event()
    payload[field] = None
    with pytest.raises(ValueError, match="identity is never inferred"):
        normalize_behavior_event(payload)


def test_rejects_invalid_or_cross_event_fields():
    with pytest.raises(ValueError, match="non-negative"):
        normalize_behavior_event(event(engagement_ms=-1))
    with pytest.raises(ValueError, match="required for key_event"):
        normalize_behavior_event(event(event_name="key_event"))
    with pytest.raises(ValueError, match="only valid"):
        normalize_behavior_event(event(key_event_name="signup"))


def test_duplicate_event_id_is_preserved_as_dedupe_key():
    first = normalize_behavior_event(event())
    retry = normalize_behavior_event(event())
    assert first["event_id"] == retry["event_id"]
