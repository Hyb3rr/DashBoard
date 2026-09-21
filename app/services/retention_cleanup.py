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


def _env_int(name: str, default: int, minimum: int = 1) -> int:
    try:
        return max(minimum, int(os.getenv(name, str(default))))
    except (TypeError, ValueError):
        return default


def _enabled() -> bool:
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
    """Delete old derived minute rows in bounded, committed chunks.

    The caller owns the connection. Each chunk commits independently, so a
    later failure cannot roll back already-completed bounded work.
    """
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


def run_once(*, now: datetime | None = None) -> dict[str, Any]:
    """Run cleanup only when explicitly enabled; failures stay scheduler-local."""
    if not _enabled():
        return {"status": "disabled", "deleted": {table: 0 for table in TABLES}, "total_deleted": 0}
    connection = postgres.connect()
    try:
        return cleanup_derived_state(connection, now=now)
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


__all__ = ["cleanup_derived_state", "run_once"]
