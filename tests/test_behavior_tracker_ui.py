from pathlib import Path


ROOT = Path(__file__).parents[1]


def test_dashboard_keeps_first_party_behavior_tracker_disabled():
    template = (ROOT / "app" / "web" / "templates" / "dashboard.html").read_text(encoding="utf-8")
    tracker = (ROOT / "app" / "web" / "static" / "behavior-tracker.js").read_text(encoding="utf-8")
    assert "/static/behavior-tracker.js" in template
    assert "enabled:false" in template
    assert "visitor_id" in tracker
    assert "session_id" in tracker
    assert "event_id" in tracker
    assert "page_view" in tracker
    assert "engagement" in tracker
    assert "key_event" in tracker
    assert "ipintel:visitor_id" in tracker
    assert "ipintel:session" in tracker
    assert "config.endpoint || '/api/behavior/events'" in tracker
    assert "/api/behavior-" + "events" not in tracker


def test_tracker_preserves_explicit_endpoint_override():
    tracker = (ROOT / "app" / "web" / "static" / "behavior-tracker.js").read_text(encoding="utf-8")
    assert "const endpoint = config.endpoint ||" in tracker


def test_tracker_does_not_derive_identity_from_network_fingerprint():
    tracker = (ROOT / "app" / "web" / "static" / "behavior-tracker.js").read_text(encoding="utf-8")
    assert "userAgent" not in tracker
    assert "fingerprint" not in tracker
    assert "remoteAddress" not in tracker
