"""Immediate logical-dedup check for the raw ClickHouse plane."""

from datetime import datetime, timedelta, timezone
import os
import uuid

import pytest

from app.db import clickhouse, postgres


@pytest.mark.integration
@pytest.mark.failure
def test_clickhouse_replay_is_one_logical_request():
    if not os.getenv("POSTGRES_DSN") or not os.getenv("CLICKHOUSE_HOST"):
        pytest.skip("native PostgreSQL and ClickHouse are required")
    postgres.ensure_schema()
    dataset = f"pytest-ch-replay-{uuid.uuid4().hex}"
    event_id = uuid.uuid4().hex.ljust(64, "0")[:64]
    event_time = datetime(2026, 8, 18, 11, 59, tzinfo=timezone.utc)
    rows = []
    for offset in (0, 1):
        rows.append({
            "timestamp": event_time,
            "ingested_at": event_time + timedelta(seconds=offset),
            "dataset_id": dataset,
            "source_id": "pytest",
            "source_offset": 10,
            "event_id": event_id,
            "src_ip": "203.0.113.250",
            "method": "GET",
            "path": "/replayed",
            "status": 200,
            "bytes_sent": 1,
            "referer": "",
            "user_agent": "pytest",
            "raw_line": "fixture",
        })
    try:
        clickhouse.insert_events(rows)
        result = clickhouse.traffic(event_time - timedelta(minutes=1), event_time + timedelta(minutes=1), 60, dataset)
        assert result["total_requests"] == 1
        assert result["unique_ips"] == 1
    finally:
        client = clickhouse.connect()
        try:
            client.command(f"ALTER TABLE http_events DELETE WHERE dataset_id = '{dataset}'")
        finally:
            client.close()
