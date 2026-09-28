"""Bounded cleanup for derived PostgreSQL data.

Raw events, replay ledgers and pending work are intentionally outside this
module. The scheduler may run this job only when explicitly enabled.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
import time
from typing import Any

from ..core import metrics
from ..db import postgres


TABLES = ("ip_minute_features", "ip_minute_path_seen")
DELTA_HISTORY_TABLE = "privacy_network_change_history"


def trim_change_log(connection: Any, keep_rows: int = 50000) -> int:
    """Keep only the newest configured number of durable change-feed rows."""
    result = connection.execute(
        """DELETE FROM ip_change_log
           WHERE seq <= (SELECT CASE WHEN MAX(seq) > %s THEN MAX(seq) - %s ELSE 0 END
                         FROM ip_change_log)""",
        (keep_rows, keep_rows),
    )
    connection.commit()
    deleted = max(0, int(result.rowcount or 0))
    metrics.increment("retention.change_log_rows_deleted", deleted)
    return deleted


def run_change_log_retention() -> dict[str, Any]:
    """Run change-feed retention on its own connection, independently of AI."""
    connection = postgres.connect()
    try:
        deleted = trim_change_log(connection)
        return {"status": "completed", "deleted": deleted}
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _env_int(name: str, default: int, minimum: int = 1) -> int:
    """Read an integer setting and clamp it to the configured minimum."""
    try:
        return max(minimum, int(os.getenv(name, str(default))))
    except (TypeError, ValueError):
        return default


def _enabled() -> bool:
    """Return whether scheduled derived-state retention is explicitly enabled."""
    return os.getenv("RETENTION_CLEANUP_ENABLED", "false").strip().lower() in {
        "1", "true", "yes", "on"
    }


def cleanup_derived_state(
    connection: Any,
    *,
    now: datetime | None = None,
    retention_days: int | None = None,
    max_rows: int | None = None,
    chunk_size: int | None = None,
    max_seconds: float | None = None,
) -> dict[str, Any]:
    """Delete stale derived minute rows in bounded chunks that commit independently."""
    now = now or datetime.now(timezone.utc)
    retention_days = retention_days or _env_int("RETENTION_MINUTE_STATE_DAYS", 37)
    max_rows = max_rows or _env_int("RETENTION_MAX_ROWS_PER_RUN", 5000)
    chunk_size = chunk_size or min(_env_int("RETENTION_CHUNK_SIZE", 500), max_rows)
    max_seconds = max_seconds if max_seconds is not None else max(0.1, float(os.getenv("RETENTION_MAX_SECONDS", "5")))
    cutoff = now - timedelta(days=retention_days)
    started = time.monotonic()
    deleted: dict[str, int] = {table: 0 for table in TABLES}
    remaining = max_rows

    for table in TABLES:
        while remaining > 0 and time.monotonic() - started < max_seconds:
            limit = min(chunk_size, remaining)
            result = connection.execute(
                f"""DELETE FROM {table}
                    WHERE ctid IN (
                        SELECT ctid FROM {table}
                         WHERE bucket_minute < %s
                         ORDER BY bucket_minute, dataset_id, ip
                         LIMIT %s
                    )""",
                (cutoff, limit),
            )
            count = max(0, int(result.rowcount or 0))
            connection.commit()
            deleted[table] += count
            remaining -= count
            if count < limit:
                break

    total = sum(deleted.values())
    metrics.increment("retention.rows_deleted", total)
    metrics.observe("retention.cleanup_ms", (time.monotonic() - started) * 1000)
    return {
        "status": "completed",
        "cutoff": cutoff.isoformat(),
        "retention_days": retention_days,
        "max_rows": max_rows,
        "deleted": deleted,
        "total_deleted": total,
        "bounded": remaining == 0 or time.monotonic() - started >= max_seconds,
    }


def cleanup_privacy_change_history(
    connection: Any,
    *,
    now: datetime | None = None,
    retention_days: int | None = None,
    max_rows: int | None = None,
    chunk_size: int | None = None,
    max_seconds: float | None = None,
) -> dict[str, Any]:
    """Bounded cleanup for delta history; never touches legacy history."""
    now = now or datetime.now(timezone.utc)
    retention_days = retention_days or _env_int("PRIVACY_HISTORY_RETENTION_DAYS", 180)
    max_rows = max_rows or _env_int("RETENTION_MAX_ROWS_PER_RUN", 5000)
    chunk_size = chunk_size or min(_env_int("RETENTION_CHUNK_SIZE", 500), max_rows)
    max_seconds = max_seconds if max_seconds is not None else max(0.1, float(os.getenv("RETENTION_MAX_SECONDS", "5")))
    cutoff = now - timedelta(days=retention_days)
    started = time.monotonic()
    deleted = 0
    remaining = max_rows
    while remaining > 0 and time.monotonic() - started < max_seconds:
        limit = min(chunk_size, remaining)
        result = connection.execute(
            f"""DELETE FROM {DELTA_HISTORY_TABLE}
                WHERE ctid IN (
                  SELECT ctid FROM {DELTA_HISTORY_TABLE}
                   WHERE changed_at < %s
                   ORDER BY changed_at, id
                   LIMIT %s
                )""",
            (cutoff, limit),
        )
        count = max(0, int(result.rowcount or 0))
        connection.commit()
        deleted += count
        remaining -= count
        if count < limit:
            break
    metrics.increment("retention.privacy_change_history_rows_deleted", deleted)
    return {
        "status": "completed", "table": DELTA_HISTORY_TABLE,
        "cutoff": cutoff.isoformat(), "retention_days": retention_days,
        "max_rows": max_rows, "deleted": deleted,
        "bounded": remaining == 0 or time.monotonic() - started >= max_seconds,
    }


def run_once(*, now: datetime | None = None) -> dict[str, Any]:
    """Run cleanup only when explicitly enabled; failures stay scheduler-local."""
    if not _enabled():
        return {"status": "disabled", "deleted": {table: 0 for table in TABLES}, "total_deleted": 0}
    connection = postgres.connect()
    try:
        result = cleanup_derived_state(connection, now=now)
        if os.getenv("PRIVACY_HISTORY_CLEANUP_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"}:
            result["privacy_change_history"] = cleanup_privacy_change_history(connection, now=now)
        else:
            result["privacy_change_history"] = {"status": "disabled", "deleted": 0}
        return result
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


__all__ = ["cleanup_derived_state", "run_change_log_retention", "run_once"]
