from datetime import datetime, timedelta, timezone

import pytest

from app.core import db
from app.core.logs import import_apache_lines
from app.services.classification_watcher import _mark_alert_delivered, _record_state
from app.services.telegram import format_bad_alert


@pytest.fixture
def isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "hub.db")
    monkeypatch.setattr(db, "REGION_SEED_PATH", tmp_path / "missing.seed.json")


def test_behavior_rebuild_writes_change_log(isolated_db):
    conn = db.connect()
    try:
        line = '198.51.100.9 - - [15/Aug/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 12 "-" "ua"'
        import_apache_lines(conn, [line], "test")
        conn.commit()
        assert conn.execute("SELECT COUNT(*) AS n FROM ip_change_log WHERE reason='behavior'").fetchone()["n"] == 1

        import_apache_lines(conn, [line], "test")
        conn.commit()
        assert conn.execute("SELECT COUNT(*) AS n FROM ip_change_log WHERE reason='behavior'").fetchone()["n"] == 1
    finally:
        conn.close()


def test_classification_state_alerts_only_on_bad_transition(isolated_db, monkeypatch):
    monkeypatch.setenv("TELEGRAM_ALERT_COOLDOWN_SECONDS", "3600")
    conn = db.connect()
    now = datetime.now(timezone.utc)
    try:
        good = {"label": "good", "score": 0, "confidence": 70}
        bad = {"label": "bad", "score": 80, "confidence": 90}
        assert _record_state(conn, "198.51.100.9", good, now) is False
        assert _record_state(conn, "198.51.100.9", bad, now) is True
        _mark_alert_delivered(conn, "198.51.100.9", now)
        assert _record_state(conn, "198.51.100.9", bad, now + timedelta(minutes=5)) is False
        assert _record_state(conn, "198.51.100.9", {"label": "watch", "score": 30, "confidence": 80}, now) is False
        assert _record_state(conn, "198.51.100.9", bad, now + timedelta(minutes=6)) is False
    finally:
        conn.close()


def test_bad_alert_contains_score_reasons():
    message = format_bad_alert(
        "198.51.100.9",
        {
            "score": 80,
            "confidence": 90,
            "score_breakdown": {"behavior_a": 80, "identity_b": 0, "trust_c": 0, "region_d": 0, "ai_e": 0, "correlation_f": 0},
            "score_explanations": {"A": "A = 80: probe burst", "C": "C = 0: behavior overrides trust"},
            "evidence": ["A — sensitive path probing (+50)"],
        },
        {"organization": "Example <Org>", "asn": "AS64500", "is_hosting": False},
        {"recent_requests": 10, "recent_status_4xx": 8, "recent_status_5xx": 1, "recent_sensitive_probe_requests": 2},
    )
    assert "198.51.100.9" in message
    assert "behavior overrides trust" in message
    assert "&lt;Org&gt;" in message
