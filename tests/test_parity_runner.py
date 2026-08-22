from datetime import datetime, timezone

import pytest

from app.db.parity import normalize_detections
from app.testing.clock import freeze, utcnow
from app.testing.failpoints import CrashFailpoint, NoopFailpoint
from app.testing.parity_runner import compare, format_report


@pytest.mark.parity
def test_clock_freeze_is_deterministic():
    fixed = datetime(2026, 8, 18, 12, tzinfo=timezone.utc)
    with freeze(fixed):
        assert utcnow() == fixed
    assert utcnow() != fixed


@pytest.mark.parity
def test_failpoint_only_crashes_at_target():
    hook = CrashFailpoint("after_pg_commit")
    hook.hit("after_parse")
    assert hook.hits == ["after_parse"]
    try:
        hook.hit("after_pg_commit")
    except RuntimeError as exc:
        assert "after_pg_commit" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("failpoint did not crash")
    assert isinstance(NoopFailpoint(), NoopFailpoint)


@pytest.mark.parity
def test_parity_report_is_semantic_and_actionable():
    report = compare(
        {"203.0.113.1": {"requests": 2}},
        {"203.0.113.1": {"requests": 2}},
        {"203.0.113.1": {"observation": {"requests": 2}, "classification": {"label": "good"}}},
        {"203.0.113.1": {"observation_payload": {"requests": 2}, "label": "good"}},
        {"total_requests": 2, "top_paths": [{"path": "/", "requests": 2}]},
        {"total_requests": 2, "top_paths": [{"path": "/", "requests": 2}]},
        traffic_fields=("total_requests", "top_paths"),
    )
    assert report.passed
    assert "status: PASS" in format_report(report)


@pytest.mark.parity
def test_detections_normalize_storage_order():
    values = normalize_detections([
        {"rule_id": "B", "window": "1h", "points": 2},
        {"id": "A", "window": "24h", "points": 1},
    ])
    assert [item[0] for item in values] == ["A", "B"]
