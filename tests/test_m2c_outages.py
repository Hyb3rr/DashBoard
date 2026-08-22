"""M2C outage simulations for the live PostgreSQL + ClickHouse path."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import os
from uuid import uuid4

import pytest

from app.db import clickhouse, postgres
from app.db.repositories import PgDetectionRepository
from app.services import classification_watcher
from app.testing.failpoints import CrashFailpoint


NOW = datetime(2026, 8, 18, 12, tzinfo=timezone.utc)


def _require_native() -> None:
    if not os.getenv("POSTGRES_DSN") or not os.getenv("CLICKHOUSE_HOST"):
        pytest.skip("POSTGRES_DSN and CLICKHOUSE_HOST are required")


def _event(ip: str, event_id: str, offset: int = 0) -> dict:
    return {
        "src_ip": ip,
        "timestamp": "2026-08-18T11:59:01+00:00",
        "method": "GET",
        "path": "/probe",
        "status": 404,
        "bytes_sent": 10,
        "referer": None,
        "user_agent": "m2c-outage-fixture",
        "source_offset": offset,
        "event_id": event_id,
        "ingested_at": NOW,
        "raw_line": f"{ip} /probe {offset}",
    }


def _cleanup_pg(ip: str, source: str, batches: tuple[str, ...]) -> None:
    with postgres.transaction() as conn:
        for table in (
            "alert_outbox", "ip_change_log", "ip_classification_state",
            "ip_observations_state", "ip_minute_path_seen", "ip_minute_features",
        ):
            conn.execute(f"DELETE FROM {table} WHERE ip=%s", (ip,))
        conn.execute("DELETE FROM processed_batches WHERE batch_id = ANY(%s)", (list(batches),))
        conn.execute("DELETE FROM log_sources WHERE source_id=%s", (source,))


def _cleanup_ch(dataset: str) -> None:
    client = clickhouse.connect()
    try:
        client.command(
            "ALTER TABLE http_events DELETE WHERE dataset_id = {dataset:String}",
            parameters={"dataset": dataset},
        )
    finally:
        client.close()


@pytest.mark.integration
@pytest.mark.failure
@pytest.mark.outage
def test_clickhouse_down_does_not_advance_pg_state(monkeypatch):
    _require_native()
    ip = "198.51.100.210"
    source = f"m2c-ch-down-{uuid4().hex}"
    batch = f"m2c-ch-down-{uuid4().hex}"
    dataset = f"m2c-ch-down-{uuid4().hex}"
    event = _event(ip, f"m2c-ch-event-{uuid4().hex}")
    try:
        monkeypatch.setenv("CLICKHOUSE_PORT", "1")
        with pytest.raises(Exception):
            clickhouse.insert_events([{**event, "dataset_id": dataset, "source_id": source}])
        with postgres.transaction() as conn:
            assert conn.execute(
                "SELECT COUNT(*) AS n FROM processed_batches WHERE batch_id=%s", (batch,)
            ).fetchone()["n"] == 0
            assert conn.execute(
                "SELECT COUNT(*) AS n FROM ip_minute_features WHERE ip=%s", (ip,)
            ).fetchone()["n"] == 0
    finally:
        _cleanup_pg(ip, source, (batch,))


@pytest.mark.integration
@pytest.mark.failure
@pytest.mark.outage
def test_postgres_down_replays_after_clickhouse_success(monkeypatch):
    _require_native()
    ip = "198.51.100.211"
    source = f"m2c-pg-down-{uuid4().hex}"
    batch = f"m2c-pg-down-{uuid4().hex}"
    dataset = f"m2c-pg-down-{uuid4().hex}"
    event = _event(ip, f"m2c-pg-event-{uuid4().hex}")
    rows = [{**event, "dataset_id": dataset, "source_id": source}]
    original_connect = postgres.connect
    try:
        clickhouse.insert_events(rows)
        monkeypatch.setattr(postgres, "connect", lambda: (_ for _ in ()).throw(ConnectionError("PG down")))
        with pytest.raises(ConnectionError, match="PG down"):
            PgDetectionRepository().process_events(
                rows, batch, dataset, source, 0, 100, "access", "live", now=NOW
            )
        monkeypatch.setattr(postgres, "connect", original_connect)
        clickhouse.insert_events(rows)
        result = PgDetectionRepository().process_events(
            rows, batch, dataset, source, 0, 100, "access", "live", now=NOW
        )
        assert result["processed"] is True
        with postgres.transaction() as conn:
            assert conn.execute(
                "SELECT requests FROM ip_minute_features WHERE dataset_id=%s AND ip=%s",
                (dataset, ip),
            ).fetchone()["requests"] == 1
            assert conn.execute(
                "SELECT last_offset FROM log_sources WHERE source_id=%s", (source,)
            ).fetchone()["last_offset"] == 100
        traffic = clickhouse.traffic(
            datetime(2026, 8, 18, 11, 58, tzinfo=timezone.utc), NOW, 60, dataset_id=dataset
        )
        assert traffic["total_requests"] == 1
        assert traffic["unique_ips"] == 1
    finally:
        monkeypatch.setattr(postgres, "connect", original_connect)
        _cleanup_pg(ip, source, (batch,))
        _cleanup_ch(dataset)


@pytest.mark.integration
@pytest.mark.failure
@pytest.mark.outage
def test_telegram_down_leaves_pg_alert_pending(monkeypatch):
    _require_native()
    ip = "198.51.100.212"
    key = f"m2c-telegram-{uuid4().hex}"
    postgres.ensure_schema()
    try:
        due_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        with postgres.transaction() as conn:
            conn.execute("DELETE FROM alert_outbox WHERE idempotency_key=%s", (key,))
            conn.execute(
                """INSERT INTO alert_outbox
                   (ip,event_type,payload,status,attempts,next_retry_at,idempotency_key)
                   VALUES (%s,'classification_bad',%s::jsonb,'pending',0,%s,%s)""",
                (ip, '{"message":"m2c outage"}', due_at, key),
            )

        async def telegram_down(_message: str) -> bool:
            return False

        monkeypatch.setattr(classification_watcher, "send_message", telegram_down)
        asyncio.run(classification_watcher._deliver_outbox_pg())
        with postgres.transaction() as conn:
            row = conn.execute(
                "SELECT status,attempts,last_error FROM alert_outbox WHERE idempotency_key=%s",
                (key,),
            ).fetchone()
        assert row["status"] == "pending"
        assert row["attempts"] == 1
        assert row["last_error"] == "telegram_delivery_failed"
    finally:
        with postgres.transaction() as conn:
            conn.execute("DELETE FROM alert_outbox WHERE idempotency_key=%s", (key,))


@pytest.mark.integration
@pytest.mark.failure
@pytest.mark.outage
def test_collector_crash_after_commit_restarts_without_double_count():
    _require_native()
    ip = "198.51.100.213"
    source = f"m2c-restart-{uuid4().hex}"
    batch = f"m2c-restart-{uuid4().hex}"
    dataset = f"m2c-restart-{uuid4().hex}"
    event = _event(ip, f"m2c-restart-event-{uuid4().hex}")
    rows = [{**event, "dataset_id": dataset, "source_id": source}]
    try:
        clickhouse.insert_events(rows)
        repo = PgDetectionRepository()
        repo.process_events(rows, batch, dataset, source, 0, 100, "access", "live", now=NOW)
        with pytest.raises(RuntimeError, match="before_ack"):
            CrashFailpoint("before_ack").hit("before_ack")
        clickhouse.insert_events(rows)
        result = repo.process_events(rows, batch, dataset, source, 0, 100, "access", "live", now=NOW)
        assert result["duplicate"] is True
        with postgres.transaction() as conn:
            assert conn.execute(
                "SELECT requests FROM ip_minute_features WHERE dataset_id=%s AND ip=%s",
                (dataset, ip),
            ).fetchone()["requests"] == 1
            assert conn.execute(
                "SELECT last_offset FROM log_sources WHERE source_id=%s", (source,)
            ).fetchone()["last_offset"] == 100
        traffic = clickhouse.traffic(
            datetime(2026, 8, 18, 11, 58, tzinfo=timezone.utc), NOW, 60, dataset_id=dataset
        )
        assert traffic["total_requests"] == 1
    finally:
        _cleanup_pg(ip, source, (batch,))
        _cleanup_ch(dataset)
