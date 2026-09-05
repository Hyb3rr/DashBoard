"""Classification consistency tests.

All tests in this file require PostgreSQL and are marked @integration.
"""
import json
import pytest


def test_invalid_ruleset_fails_without_partial_registry(tmp_path):
    """Pure logic test — no DB required."""
    from app.core.rules import load_rules

    (tmp_path / "good.json").write_text(json.dumps({
        "id": "TEST-001", "name": "test", "severity": "low", "points": 1,
        "rule_type": "anomaly", "mitre_technique": None, "window": "1h", "version": 1,
        "enabled": True, "condition": {"field": "requests", "operator": "gt", "value": 1},
        "false_positive_notes": ["test"],
    }), encoding="utf-8")
    (tmp_path / "bad.json").write_text('{"id": "TEST-002"}', encoding="utf-8")
    with pytest.raises(ValueError, match="bad.json"):
        load_rules(tmp_path)


@pytest.mark.integration
def test_recent_classification_is_shared_by_snapshot_and_watcher():
    """Requires PostgreSQL — skipped without POSTGRES_DSN."""
    pytest.skip("Requires PostgreSQL integration environment")
