from datetime import datetime, timedelta, timezone

from app.core.rules import BehaviorContext, run_rules
from app.db.repositories import PgDetectionRepository, _rolling_peak_5m


UTC = timezone.utc


def _minute(value: str, requests: int) -> dict:
    return {"bucket_minute": value, "requests": requests}


def test_rolling_peak_5m_normalizes_time_and_sums_duplicate_minutes():
    rows = [
        _minute("2026-08-31T00:00:00Z", 2),
        _minute("2026-08-31T00:00:00+00:00", 3),
        _minute("2026-08-31T00:01:00+00:00", 1),
        _minute("2026-08-31T00:03:00+00:00", 1),
        _minute("2026-08-31T00:04:00+00:00", 1),
    ]

    assert _rolling_peak_5m(rows) == 8
    assert _rolling_peak_5m(list(reversed(rows))) == 8


def test_rolling_peak_5m_does_not_compress_missing_minutes():
    rows = [
        _minute("2026-08-31T00:00:00+00:00", 1),
        _minute("2026-08-31T00:01:00+00:00", 1),
        _minute("2026-08-31T00:03:00+00:00", 1),
        _minute("2026-08-31T00:04:00+00:00", 1),
    ]

    assert _rolling_peak_5m(rows) == 4


def test_production_score_uses_rolling_peak_for_web_rate_rule():
    now = datetime(2026, 8, 31, 0, 5, tzinfo=UTC)
    row = {
        "requests": 100,
        "peak_requests_1m": 50,
        "peak_requests_5m": 100,
        "status_4xx": 0,
        "unique_paths": 0,
        "sensitive_probe_requests": 0,
        "first_seen": now - timedelta(minutes=5),
        "last_seen": now,
    }

    score, _level, _evidence, detections = PgDetectionRepository._score(row, "1h")

    assert score >= 10
    assert any(item["id"] == "WEB-RATE-001" for item in detections)
    assert any(item.id == "WEB-RATE-001" for item in run_rules(
        BehaviorContext(peak_requests_5m=100), "1h"
    ))


class _Result:
    def __init__(self, rows):
        self._rows = rows

    def fetchall(self):
        return self._rows


class _AggregateConnection:
    def execute(self, query, _params):
        if "FROM ip_minute_path_seen" in query:
            return _Result([{"ip": "203.0.113.1", "unique_paths": 1, "peak_requests_1m": 50}])
        if "bucket_minute, requests" in query:
            return _Result([
                _minute("2026-08-31T00:03:00Z", 50) | {"ip": "203.0.113.1"},
                _minute("2026-08-31T00:04:00+00:00", 50) | {"ip": "203.0.113.1"},
            ])
        return _Result([{
            "ip": "203.0.113.1", "requests": 100, "status_2xx": 100,
            "status_3xx": 0, "status_4xx": 0, "status_5xx": 0,
            "post_requests": 0, "sensitive_hits": 0, "wp_login_hits": 0,
            "bot_hits": 0, "first_seen": datetime(2026, 8, 31, tzinfo=UTC),
            "last_seen": datetime(2026, 8, 31, 0, 4, tzinfo=UTC),
        }])


def test_aggregate_many_wires_rolling_peak_into_production_score():
    now = datetime(2026, 8, 31, 0, 5, tzinfo=UTC)
    lifetime, _recent, one_hour = PgDetectionRepository._aggregate_many(
        _AggregateConnection(), "live", {"203.0.113.1"}, now
    )["203.0.113.1"]

    assert lifetime["peak_requests_5m"] == 100
    assert one_hour["peak_requests_5m"] == 100
    assert any(item["id"] == "WEB-RATE-001" for item in PgDetectionRepository._score(one_hour, "1h")[3])
