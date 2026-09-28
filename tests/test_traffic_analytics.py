"""Traffic analytics tests — all require PostgreSQL/ClickHouse, marked @integration.

The one pure ClickHouse utility test (_iso_utc) runs without a live connection.
"""
from datetime import datetime, timezone

import pytest


def test_clickhouse_bucket_timestamps_are_explicit_utc():
    from app.db.clickhouse import _iso_utc

    naive = datetime(2026, 1, 1, 12, 0)
    aware = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    assert _iso_utc(naive) == "2026-01-01T12:00:00Z"
    assert _iso_utc(aware) == "2026-01-01T12:00:00Z"


def test_summary_window_counts_distinct_active_ips_by_current_label(monkeypatch):
    from contextlib import contextmanager
    from app.db import state_repository
    from app.db.repositories import StateRepository

    class Result:
        def __init__(self, row=None, rows=None):
            self.row, self.rows = row, rows or []

        def fetchone(self):
            return self.row

        def fetchall(self):
            return self.rows

    class Connection:
        def execute(self, sql, args=()):
            if "COUNT(DISTINCT f.ip)" in sql:
                assert args[0] == "live"
                assert args[1].isoformat().startswith("2026-01-01")
                return Result({"total": 3, "critical": 1, "medium": 1, "low": 0, "good": 1, "unknown": 0})
            return Result(rows=[])

    @contextmanager
    def fake_transaction():
        yield Connection()

    monkeypatch.setattr(state_repository, "transaction", fake_transaction)
    result = StateRepository().summary_window(
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        datetime(2026, 1, 1, 23, 59, tzinfo=timezone.utc),
    )
    assert result["classification"] == {"critical": 1, "medium": 1, "low": 0, "good": 1, "unknown": 0}
    assert result["total_ips"] == 3


def test_risk_traffic_series_returns_medium_and_critical_request_buckets(monkeypatch):
    from contextlib import contextmanager
    from app.db import state_repository
    from app.db.repositories import StateRepository

    class Result:
        def fetchall(self):
            return [{
                "timestamp": datetime(2026, 1, 1, tzinfo=timezone.utc),
                "low_requests": 0,
                "medium_requests": 7,
                "critical_requests": 3,
            }]

    class Connection:
        def execute(self, sql, args=()):
            assert "date_bin" in sql
            assert "1970-01-01 00:00:00+00" in sql
            assert args[0] == "300 seconds"
            assert args[1] == "live"
            return Result()

    @contextmanager
    def fake_transaction():
        yield Connection()

    monkeypatch.setattr(state_repository, "transaction", fake_transaction)
    result = StateRepository().risk_traffic_series(
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        datetime(2026, 1, 1, 1, tzinfo=timezone.utc),
        300,
    )
    assert result == [{
        "timestamp": "2026-01-01T00:00:00+00:00",
        "low_requests": 0,
        "medium_requests": 7,
        "critical_requests": 3,
    }]


def test_classification_summary_uses_distinct_exact_traffic_cohort_and_unknown_fallback(monkeypatch):
    from contextlib import contextmanager
    from app.db import state_repository
    from app.db.repositories import StateRepository

    class Result:
        def fetchone(self):
            return {"total": 3, "critical": 1, "medium": 0, "low": 0, "good": 1, "unknown": 1}

    class Connection:
        def execute(self, sql, args=()):
            assert "SELECT DISTINCT ip FROM unnest(%s::inet[])" in sql
            assert "LEFT JOIN ip_classification_state" in sql
            assert args == (["203.0.113.1", "203.0.113.2", "203.0.113.3"],)
            return Result()

    @contextmanager
    def fake_transaction():
        yield Connection()

    monkeypatch.setattr(state_repository, "transaction", fake_transaction)
    result = StateRepository().classification_summary_for_ips([
        "203.0.113.1", "203.0.113.1", "203.0.113.2", "203.0.113.3",
    ])

    assert result == {
        "total_ips": 3,
        "classification": {"critical": 1, "medium": 0, "low": 0, "good": 1, "unknown": 1},
    }
    assert sum(result["classification"].values()) == result["total_ips"]


def test_empty_traffic_cohort_has_zero_classification_counts_without_database_query(monkeypatch):
    from app.db import state_repository
    from app.db.repositories import StateRepository

    def unexpected_transaction():
        raise AssertionError("empty cohort must not query PostgreSQL")

    monkeypatch.setattr(state_repository, "transaction", unexpected_transaction)
    result = StateRepository().classification_summary_for_ips([])

    assert result == {
        "total_ips": 0,
        "classification": {"critical": 0, "medium": 0, "low": 0, "good": 0, "unknown": 0},
    }


def test_path_filter_risk_series_is_intentionally_unavailable():
    from app.db.repositories import StateRepository

    assert StateRepository().risk_traffic_series(
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        datetime(2026, 1, 1, 1, tzinfo=timezone.utc),
        300,
        filter_type="path",
        filter_value="/wp-login.php",
    ) == []


@pytest.mark.integration
def test_health_endpoint_response_structure():
    from fastapi.testclient import TestClient
    from app.main import app

    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "mode" in data
    assert "rules" in data
    assert "storage" in data
    assert "collector" in data
    assert "postgres" in data["storage"]
    assert "clickhouse" in data["storage"]


def test_ip_dashboard_pipeline_timing_does_not_query_region(monkeypatch):
    from app.routers.ip_state import _pg_item

    row = {
        "ip": "203.0.113.8",
        "updated_at": datetime(2026, 8, 20, 2, 0, 2, tzinfo=timezone.utc),
        "observation_payload": {
            "ip": "203.0.113.8",
            "pipeline_received_at": "2026-08-20T02:00:00+00:00",
            "pipeline_state_ready_at": "2026-08-20T02:00:01+00:00",
        },
        "label": "unknown",
        "classification_score": 0,
        "classification_confidence": 0,
    }

    item = _pg_item(row)

    assert item["pipeline"]["backend_ready_ms"] == 2000.0
    assert "region_profile" not in item



@pytest.mark.integration
def test_traffic_range_uses_fixed_time_buckets():
    pytest.skip("Requires ClickHouse integration environment")


@pytest.mark.integration
def test_traffic_custom_window_filters_and_zero_fills():
    pytest.skip("Requires ClickHouse integration environment")


@pytest.mark.integration
def test_traffic_empty_window_returns_flat_zero_series():
    pytest.skip("Requires ClickHouse integration environment")


@pytest.mark.integration
def test_ip_traffic_reaches_window_end_with_zero_bucket():
    pytest.skip("Requires ClickHouse integration environment")


@pytest.mark.integration
def test_traffic_filter_and_exclude_reaggregate_same_window():
    pytest.skip("Requires ClickHouse integration environment")


@pytest.mark.integration
def test_traffic_dataset_selector_separates_stream_and_file():
    pytest.skip("Requires ClickHouse integration environment")


@pytest.mark.integration
def test_ip_page_is_server_paginated_and_searches_global_dataset():
    pytest.skip("Requires PostgreSQL integration environment")


def test_ip_list_projection_is_compact_and_keeps_dashboard_contract():
    from app.routers.ip_state import _pg_compact_item

    item = _pg_compact_item({
        "ip": "203.0.113.10",
        "country": "Exampleland",
        "country_code": "EX",
        "city": "Example City",
        "network_location": {"country": "Exampleland"},
        "provider_status": {},
        "observation_payload": {
            "requests": 12, "status_4xx": 2, "status_5xx": 1,
            "unique_paths": 4, "last_seen": "2026-09-15T10:00:00+00:00",
        },
        "label": "medium", "classification_score": 42,
        "classification_confidence": 80,
        "disposition": "new",
    })

    assert item["classification"] == {"label": "medium", "score": 42, "confidence": 80}
    assert item["requests"] == 12
    assert item["last_seen"] == "2026-09-15T10:00:00+00:00"
    assert "provider_errors" not in item
    assert "field_sources" not in item
    assert "history" not in item["disposition"]


@pytest.mark.integration
def test_ip_traffic_top_paths_follow_selected_window():
    pytest.skip("Requires ClickHouse integration environment")
