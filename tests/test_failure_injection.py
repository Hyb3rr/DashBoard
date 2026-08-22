"""M2B.7 replay/rollback tests.

The native PostgreSQL case is skipped unless POSTGRES_DSN is supplied. This
keeps the default unit suite portable while allowing CI/staging to run the
real transaction test against the local PostgreSQL service.
"""

from datetime import datetime, timezone
import os

import pytest

from app.db import postgres
from app.db.repositories import PgDetectionRepository
from app.testing.clock import freeze
from app.testing.failpoints import CrashFailpoint


IN_TRANSACTION_FAILPOINTS = (
    "after_processed_batch_insert", "after_feature_upsert", "after_detection",
    "after_classification", "after_alert_outbox", "before_checkpoint",
    "after_checkpoint", "before_pg_commit",
)


@pytest.mark.integration
@pytest.mark.failure
def test_pg_crash_rollback_and_post_commit_replay():
    dsn = os.getenv("POSTGRES_DSN")
    if not dsn:
        pytest.skip("POSTGRES_DSN is required for native failure injection")
    ip = "198.51.100.247"
    source = "pytest-failure-source"
    dataset = "pytest-failure-dataset"
    batches = ("pytest-before-commit", "pytest-after-commit")
    now = datetime(2026, 8, 18, 12, tzinfo=timezone.utc)
    event = {
        "src_ip": ip, "timestamp": "2026-08-18T11:59:01+00:00",
        "method": "GET", "path": "/probe", "status": 404,
        "bytes_sent": 10, "referer": None, "user_agent": "fixture",
    }
    postgres.ensure_schema()
    with postgres.transaction() as conn:
        for table in ("alert_outbox", "ip_change_log", "ip_classification_state",
                      "ip_observations_state", "ip_minute_path_seen", "ip_minute_features"):
            conn.execute(f"DELETE FROM {table} WHERE ip=%s", (ip,))
        conn.execute("DELETE FROM processed_batches WHERE batch_id = ANY(%s)", (list(batches),))
        conn.execute("DELETE FROM log_sources WHERE source_id=%s", (source,))

    repo = PgDetectionRepository()
    try:
        with freeze(now):
            with pytest.raises(RuntimeError, match="before_pg_commit"):
                repo.process_events([event], batches[0], dataset, source, 0, 100,
                                    "access", "live", now=now,
                                    failpoint=CrashFailpoint("before_pg_commit"))
            with postgres.transaction() as conn:
                assert conn.execute("SELECT COUNT(*) AS n FROM processed_batches WHERE batch_id=%s",
                                    (batches[0],)).fetchone()["n"] == 0
                assert conn.execute("SELECT COUNT(*) AS n FROM ip_minute_features WHERE ip=%s",
                                    (ip,)).fetchone()["n"] == 0

            assert repo.process_events([event], batches[0], dataset, source, 0, 100,
                                       "access", "live", now=now)["processed"]
            assert repo.process_events([event], batches[0], dataset, source, 0, 100,
                                       "access", "live", now=now)["duplicate"]

            with pytest.raises(RuntimeError, match="after_pg_commit"):
                repo.process_events([event], batches[1], dataset, source, 100, 200,
                                    "access", "live", now=now,
                                    failpoint=CrashFailpoint("after_pg_commit"))
            assert repo.process_events([event], batches[1], dataset, source, 100, 200,
                                       "access", "live", now=now)["duplicate"]

            with postgres.transaction() as conn:
                assert conn.execute("SELECT requests FROM ip_minute_features WHERE ip=%s",
                                    (ip,)).fetchone()["requests"] == 2
                assert conn.execute("SELECT last_offset FROM log_sources WHERE source_id=%s",
                                    (source,)).fetchone()["last_offset"] == 200
    finally:
        with postgres.transaction() as conn:
            for table in ("alert_outbox", "ip_change_log", "ip_classification_state",
                          "ip_observations_state", "ip_minute_path_seen", "ip_minute_features"):
                conn.execute(f"DELETE FROM {table} WHERE ip=%s", (ip,))
            conn.execute("DELETE FROM processed_batches WHERE batch_id = ANY(%s)", (list(batches),))
            conn.execute("DELETE FROM log_sources WHERE source_id=%s", (source,))


@pytest.mark.integration
def test_traffic_always_advances_realtime_cursor_when_label_is_unchanged():
    dsn = os.getenv("POSTGRES_DSN")
    if not dsn:
        pytest.skip("POSTGRES_DSN is required for native repository tests")
    ip = "198.51.100.249"
    source = "pytest-realtime-cursor"
    dataset = "pytest-realtime-dataset"
    batches = ("pytest-realtime-one", "pytest-realtime-two")
    event = {"src_ip": ip, "timestamp": "2026-08-18T11:59:01+00:00", "method": "GET",
             "path": "/probe", "status": 200, "bytes_sent": 10, "referer": None, "user_agent": "fixture"}
    postgres.ensure_schema()
    try:
        with postgres.transaction() as conn:
            for table in ("ip_change_log", "ip_classification_state", "ip_observations_state",
                          "ip_minute_path_seen", "ip_minute_features"):
                conn.execute(f"DELETE FROM {table} WHERE ip=%s", (ip,))
            conn.execute("DELETE FROM processed_batches WHERE batch_id = ANY(%s)", (list(batches),))
            conn.execute("DELETE FROM log_sources WHERE source_id=%s", (source,))
        repo = PgDetectionRepository()
        with freeze(datetime(2026, 8, 18, 12, tzinfo=timezone.utc)):
            assert repo.process_events([event], batches[0], "live", source, 0, 100, "access", "live")["processed"]
            with postgres.transaction() as conn:
                first_cursor = conn.execute("SELECT COALESCE(MAX(seq), 0) AS n FROM ip_change_log").fetchone()["n"]
            assert repo.process_events([event], batches[1], "live", source, 100, 200, "access", "live")["processed"]
            with postgres.transaction() as conn:
                rows = conn.execute("SELECT reason FROM ip_change_log WHERE ip=%s ORDER BY seq", (ip,)).fetchall()
                second_cursor = conn.execute("SELECT COALESCE(MAX(seq), 0) AS n FROM ip_change_log").fetchone()["n"]
            assert second_cursor > first_cursor
            assert [row["reason"] for row in rows].count("traffic") == 2
    finally:
        with postgres.transaction() as conn:
            for table in ("ip_change_log", "ip_classification_state", "ip_observations_state",
                          "ip_minute_path_seen", "ip_minute_features"):
                conn.execute(f"DELETE FROM {table} WHERE ip=%s", (ip,))
            conn.execute("DELETE FROM processed_batches WHERE batch_id = ANY(%s)", (list(batches),))
            conn.execute("DELETE FROM log_sources WHERE source_id=%s", (source,))


@pytest.mark.integration
@pytest.mark.failure
@pytest.mark.parametrize("failpoint_name", IN_TRANSACTION_FAILPOINTS)
def test_pg_internal_failpoints_rollback_then_replay(failpoint_name):
    dsn = os.getenv("POSTGRES_DSN")
    if not dsn:
        pytest.skip("POSTGRES_DSN is required for native failure injection")
    ip = "198.51.100.248"
    source = f"pytest-failure-{failpoint_name}"
    dataset = f"pytest-failure-{failpoint_name}"
    batch = f"pytest-batch-{failpoint_name}"
    now = datetime(2026, 8, 18, 12, tzinfo=timezone.utc)
    event = {"src_ip": ip, "timestamp": "2026-08-18T11:59:01+00:00", "method": "GET",
             "path": "/probe", "status": 404, "bytes_sent": 10, "referer": None, "user_agent": "fixture"}
    postgres.ensure_schema()
    with postgres.transaction() as conn:
        for table in ("alert_outbox", "ip_change_log", "ip_classification_state",
                      "ip_observations_state", "ip_minute_path_seen", "ip_minute_features"):
            conn.execute(f"DELETE FROM {table} WHERE ip=%s", (ip,))
        conn.execute("DELETE FROM processed_batches WHERE batch_id=%s", (batch,))
        conn.execute("DELETE FROM log_sources WHERE source_id=%s", (source,))
    try:
        repo = PgDetectionRepository()
        with freeze(now):
            with pytest.raises(RuntimeError, match=failpoint_name):
                repo.process_events([event], batch, dataset, source, 0, 100, "access", "live",
                                    now=now, failpoint=CrashFailpoint(failpoint_name))
            with postgres.transaction() as conn:
                assert conn.execute("SELECT COUNT(*) AS n FROM processed_batches WHERE batch_id=%s", (batch,)).fetchone()["n"] == 0
                assert conn.execute("SELECT COUNT(*) AS n FROM ip_minute_features WHERE ip=%s", (ip,)).fetchone()["n"] == 0
            assert repo.process_events([event], batch, dataset, source, 0, 100, "access", "live", now=now)["processed"]
            with postgres.transaction() as conn:
                assert conn.execute("SELECT requests FROM ip_minute_features WHERE ip=%s", (ip,)).fetchone()["requests"] == 1
    finally:
        with postgres.transaction() as conn:
            for table in ("alert_outbox", "ip_change_log", "ip_classification_state",
                          "ip_observations_state", "ip_minute_path_seen", "ip_minute_features"):
                conn.execute(f"DELETE FROM {table} WHERE ip=%s", (ip,))
            conn.execute("DELETE FROM processed_batches WHERE batch_id=%s", (batch,))
            conn.execute("DELETE FROM log_sources WHERE source_id=%s", (source,))
