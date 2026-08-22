"""Background classification transition watcher — PostgreSQL only."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import logging
import os
from uuid import uuid4

from ..db import postgres as postgres_store
from ..core import metrics
from .telegram import enabled as telegram_enabled, format_bad_alert, send_message

logger = logging.getLogger(__name__)
WATCH_INTERVAL_SECONDS = 5


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def _deliver_outbox() -> None:
    """Claim and deliver pending PostgreSQL alert outbox entries."""
    if not telegram_enabled():
        return
    owner = f"telegram-pg:{os.getpid()}:{uuid4().hex}"
    claimed: list[dict] = []
    now = _now()
    with postgres_store.transaction() as conn:
        conn.execute(
            "UPDATE alert_outbox SET status='pending',lease_owner=NULL,lease_until=NULL WHERE status='sending' AND lease_until < %s",
            (now,),
        )
        rows = conn.execute(
            "SELECT * FROM alert_outbox WHERE status='pending' AND next_retry_at<=%s ORDER BY id LIMIT 10",
            (now,),
        ).fetchall()
        lease_until = now + timedelta(minutes=2)
        for row in rows:
            updated = conn.execute(
                "UPDATE alert_outbox SET status='sending',lease_owner=%s,lease_until=%s WHERE id=%s AND status='pending'",
                (owner, lease_until, row["id"]),
            )
            if updated.rowcount:
                claimed.append(dict(row))
    for row in claimed:
        payload = row.get("payload") or {}
        message = payload.get("message") or format_bad_alert(
            str(row["ip"]), payload.get("classification") or {}, {}, {}
        )
        delivered = await send_message(message)
        metrics.increment("alert_outbox.attempts")
        with postgres_store.transaction() as conn:
            if delivered:
                metrics.increment("alert_outbox.delivered")
                conn.execute(
                    "UPDATE alert_outbox SET status='delivered',delivered_at=%s,lease_owner=NULL,lease_until=NULL WHERE id=%s AND lease_owner=%s",
                    (_now(), row["id"], owner),
                )
            else:
                metrics.increment("alert_outbox.failed")
                attempts = int(row.get("attempts") or 0) + 1
                if attempts >= 8:
                    conn.execute(
                        "UPDATE alert_outbox SET status='failed',attempts=%s,last_error='telegram_delivery_failed',lease_owner=NULL,lease_until=NULL WHERE id=%s AND lease_owner=%s",
                        (attempts, row["id"], owner),
                    )
                else:
                    retry_at = datetime.now(timezone.utc) + timedelta(seconds=min(3600, 2 ** min(attempts, 10)))
                    conn.execute(
                        "UPDATE alert_outbox SET status='pending',attempts=%s,next_retry_at=%s,last_error='telegram_delivery_failed',lease_owner=NULL,lease_until=NULL WHERE id=%s AND lease_owner=%s",
                        (attempts, retry_at, row["id"], owner),
                    )


# Alias used by integration tests (test_m2c_outages.py)
_deliver_outbox_pg = _deliver_outbox


async def run_classification_watcher(stop_event: asyncio.Event | None = None) -> None:
    stop_event = stop_event or asyncio.Event()
    while not stop_event.is_set():
        await _deliver_outbox()
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=WATCH_INTERVAL_SECONDS)
        except asyncio.TimeoutError:
            pass
