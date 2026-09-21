from app.routers import behavior_events


def test_rate_limit_window_semantics_remain_unchanged(monkeypatch):
    monkeypatch.setattr(behavior_events, "_rate_windows", {})
    monkeypatch.setattr(behavior_events, "_last_rate_cleanup", 0.0)
    monkeypatch.setattr(behavior_events, "_RATE_LIMIT", 2)

    assert behavior_events._rate_limited("client-a", 1.0) is False
    assert behavior_events._rate_limited("client-a", 2.0) is False
    assert behavior_events._rate_limited("client-a", 3.0) is True
    assert behavior_events._rate_limited("client-a", 61.0) is False


def test_rate_limiter_periodically_removes_expired_client_buckets(monkeypatch):
    monkeypatch.setattr(behavior_events, "_rate_windows", {})
    monkeypatch.setattr(behavior_events, "_last_rate_cleanup", 0.0)

    behavior_events._rate_limited("expired-a", 1.0)
    behavior_events._rate_limited("expired-b", 2.0)
    assert set(behavior_events._rate_windows) == {"expired-a", "expired-b"}

    behavior_events._rate_limited("new-client", 62.0)

    assert set(behavior_events._rate_windows) == {"new-client"}
