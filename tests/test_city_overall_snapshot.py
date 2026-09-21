from datetime import datetime, timezone

from app.services.city_overall_snapshot import build_vietnam_snapshot


def test_vietnam_snapshot_has_reproducible_audit_shape():
    snapshot = build_vietnam_snapshot(now=datetime(2026, 9, 15, tzinfo=timezone.utc))
    assert snapshot["country_code"] == "VN"
    assert snapshot["peer_group"] == "VN-34"
    assert snapshot["model_version"] == "city-overall-v1"
    assert len(snapshot["rows"]) == 34
    assert all({"evidence_coverage", "components", "limitations"} <= row.keys() for row in snapshot["rows"])
