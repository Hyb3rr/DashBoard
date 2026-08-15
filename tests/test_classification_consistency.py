from datetime import datetime, timezone

import pytest

from app.core import db
from app.services.classification import build_classification_snapshot
from app.services.classification_watcher import _classification_for_ip


def test_recent_classification_is_shared_by_snapshot_and_watcher(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "hub.db")
    conn = db.connect()
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO ip_profiles(ip,organization,organization_confidence,fetched_at) VALUES (?,?,?,?)",
        ("198.51.100.10", "Example Net", 90, now),
    )
    conn.execute(
        """INSERT INTO ip_observations
           (ip,requests,status_4xx,behavior_score,behavior_evidence_json,detections_json,
            recent_requests,behavior_score_recent,behavior_evidence_recent_json,
            detections_recent_json,recent_updated_at,updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        ("198.51.100.10", 100, 90, 50, '["old probe"]', '[{"id":"WEB-SENSITIVE-001"}]',
         10, 0, '[]', '[]', now, now),
    )
    conn.commit()
    snapshot = build_classification_snapshot(conn, "198.51.100.10")
    watcher_classification, _, watcher_observation = _classification_for_ip(conn, "198.51.100.10")
    assert snapshot.classification == watcher_classification
    assert snapshot.observation == watcher_observation
    assert snapshot.classification["label"] != "bad"
    assert snapshot.observation["detections_recent"] == []
    conn.close()


def test_invalid_ruleset_fails_without_partial_registry(tmp_path):
    from app.core.rules import load_rules

    (tmp_path / "good.yaml").write_text("""
id: TEST-001
name: test
severity: low
points: 1
rule_type: anomaly
window: 1h
version: 1
enabled: true
condition: {field: requests, operator: gt, value: 1}
""", encoding="utf-8")
    (tmp_path / "bad.yaml").write_text("id: TEST-002\n", encoding="utf-8")
    with pytest.raises(ValueError, match="bad.yaml"):
        load_rules(tmp_path)
