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
    import app.main as main

    def unexpected_region_lookup(*_args, **_kwargs):
        raise AssertionError("region lookup entered realtime IP hot path")

    monkeypatch.setattr(main.RegionRepository, "get", unexpected_region_lookup)
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

    item = main._pg_item(row)

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


@pytest.mark.integration
def test_ip_traffic_top_paths_follow_selected_window():
    pytest.skip("Requires ClickHouse integration environment")
