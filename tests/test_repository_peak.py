from datetime import datetime, timedelta, timezone

from app.core.rules import BehaviorContext, run_rules
from app.db.repositories import (
    PgDetectionRepository,
    _build_recent_behavior_fields,
    _feature_deltas,
    _rolling_peak_5m,
    _select_recent_behavior_window,
)


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
                _minute("2026-08-31T00:03:00Z", 120) | {"ip": "203.0.113.1"},
                _minute("2026-08-31T00:04:00+00:00", 50) | {"ip": "203.0.113.1"},
            ])
        return _Result([{
            "ip": "203.0.113.1", "requests": 170, "status_2xx": 170,
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

    assert lifetime["peak_requests_5m"] == 170
    assert one_hour["peak_requests_5m"] == 170
    assert lifetime["peak_requests_1m"] == 120
    assert one_hour["peak_requests_1m"] == 120
    assert any(item["id"] == "WEB-RATE-001" for item in PgDetectionRepository._score(one_hour, "1h")[3])


def test_peak_requests_1m_uses_total_ip_minute_not_max_single_path():
    buckets, paths = _feature_deltas([
        {"timestamp": "2026-08-31T00:00:00Z", "src_ip": "203.0.113.1", "path": "/a", "status": 200},
        *[
            {"timestamp": "2026-08-31T00:00:00Z", "src_ip": "203.0.113.1", "path": "/b", "status": 200}
            for _ in range(60)
        ],
    ])
    assert buckets[("203.0.113.1", "2026-08-31T00:00:00+00:00")]["requests"] == 61
    assert len(paths) == 2


def test_feature_deltas_canonicalize_dynamic_paths_for_unique_path_counts():
    _buckets, paths = _feature_deltas([
        {"timestamp": "2026-08-31T00:00:00Z", "src_ip": "203.0.113.1", "path": "/user/1001", "status": 200},
        {"timestamp": "2026-08-31T00:00:00Z", "src_ip": "203.0.113.1", "path": "/user/1002", "status": 200},
    ])
    assert len(paths) == 1
    assert next(iter(paths))[2] == "/user/{id}"


def test_recent_classification_uses_stronger_one_hour_window_pair():
    selected = _select_recent_behavior_window(
        30, "medium", ["recent burst"], [{"id": "WEB-BURST-001"}],
        0, "low", [], [],
    )
    assert selected == (30, "medium", ["recent burst"], [{"id": "WEB-BURST-001"}])


def test_one_hour_winner_does_not_relabel_detections_24h():
    fields = _build_recent_behavior_fields(
        30, "medium", ["recent burst"], [{"id": "WEB-BURST-001"}],
        0, "low", [], [],
    )
    assert fields["recent_behavior_score"] == 30
    assert fields["detections_recent"] == [{"id": "WEB-BURST-001"}]
    assert fields["detections_24h"] == []
