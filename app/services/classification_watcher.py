"""Background classification transition watcher."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import json
import logging
import os
from uuid import uuid4

from ..core.db import connect
from ..core.change_feed import append_ip_changes
from .classification import build_classification_snapshot
from .telegram import cooldown_seconds, enabled as telegram_enabled, format_bad_alert, send_message

logger = logging.getLogger(__name__)
WATCH_INTERVAL_SECONDS = 5


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return (parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)
    except ValueError:
        return None


def _cursor(conn) -> int:
    return int(conn.execute("SELECT COALESCE(MAX(seq), 0) AS seq FROM ip_change_log").fetchone()["seq"])


CONSUMER_ID = "classification_watcher"


def _consumer_cursor(conn) -> int:
    row = conn.execute("SELECT last_seq FROM change_consumer_state WHERE consumer_id=?", (CONSUMER_ID,)).fetchone()
    if row:
        return int(row["last_seq"])
    current = _cursor(conn)
    conn.execute(
        "INSERT INTO change_consumer_state(consumer_id,last_seq,updated_at,status) VALUES (?,?,?,'active')",
        (CONSUMER_ID, current, _now().isoformat()),
    )
    conn.commit()
    return current


def _save_consumer_cursor(conn, cursor: int, status: str = "active") -> None:
    conn.execute(
        "UPDATE change_consumer_state SET last_seq=?, updated_at=?, status=? WHERE consumer_id=?",
        (cursor, _now().isoformat(), status, CONSUMER_ID),
    )


def _enqueue_alert(conn, ip: str, message: str, now: datetime) -> None:
    existing = conn.execute(
        "SELECT id FROM alert_outbox WHERE ip=? AND event_type='classification_bad' AND status IN ('pending','sending') LIMIT 1",
        (ip,),
    ).fetchone()
    if not existing:
        conn.execute(
            """INSERT INTO alert_outbox
               (ip,event_type,payload_json,status,attempts,next_retry_at,created_at,idempotency_key)
               VALUES (?, 'classification_bad', ?, 'pending', 0, ?, ?, ?)""",
            (ip, json.dumps({"message": message}), now.isoformat(), now.isoformat(),
             f"classification_bad:{ip}:{now.isoformat()}"),
        )


async def _deliver_outbox() -> None:
    if not telegram_enabled():
        return
    owner = f"telegram:{os.getpid()}:{uuid4().hex}"
    conn = connect()
    try:
        now = _now().isoformat()
        conn.execute("UPDATE alert_outbox SET status='pending',lease_owner=NULL,lease_until=NULL WHERE status='sending' AND lease_until<?", (now,))
        rows = conn.execute(
            "SELECT * FROM alert_outbox WHERE status='pending' AND next_retry_at<=? ORDER BY id LIMIT 10",
            (now,),
        ).fetchall()
        claimed = []
        lease_until = (datetime.now(timezone.utc) + timedelta(minutes=2)).isoformat()
        for row in rows:
            updated = conn.execute(
                "UPDATE alert_outbox SET status='sending',lease_owner=?,lease_until=? WHERE id=? AND status='pending'",
                (owner, lease_until, row["id"]),
            )
            if updated.rowcount:
                claimed.append(row)
        conn.commit()
    finally:
        conn.close()
    for row in claimed:
        payload = json.loads(row["payload_json"])
        delivered = await send_message(payload["message"])
        conn = connect()
        try:
            if delivered:
                conn.execute("UPDATE alert_outbox SET status='delivered', delivered_at=?,lease_owner=NULL,lease_until=NULL WHERE id=? AND lease_owner=?", (_now().isoformat(), row["id"], owner))
                _mark_alert_delivered(conn, row["ip"], _now())
            else:
                attempts = int(row["attempts"]) + 1
                if attempts >= 8:
                    conn.execute("UPDATE alert_outbox SET status='failed', attempts=?,last_error=?,lease_owner=NULL,lease_until=NULL WHERE id=? AND lease_owner=?", (attempts, "telegram_delivery_failed", row["id"], owner))
                    _clear_alert_pending(conn, row["ip"])
                else:
                    retry_at = _now().timestamp() + min(3600, 2 ** min(attempts, 10))
                    retry_iso = datetime.fromtimestamp(retry_at, timezone.utc).isoformat()
                    conn.execute("UPDATE alert_outbox SET attempts=?, next_retry_at=?,last_error=?,status='pending',lease_owner=NULL,lease_until=NULL WHERE id=? AND lease_owner=?", (attempts, retry_iso, "telegram_delivery_failed", row["id"], owner))
            conn.commit()
        finally:
            conn.close()


def _classification_for_ip(conn, ip: str):
    snapshot = build_classification_snapshot(conn, ip)
    return snapshot.classification, snapshot.profile, snapshot.observation


def _record_state(conn, ip: str, classification: dict, now: datetime) -> bool:
    previous = conn.execute("SELECT * FROM ip_classification_state WHERE ip=?", (ip,)).fetchone()
    alert = should_alert(previous, classification, now)
    previous_delivery = previous["last_alert_label"] if previous else None
    if alert:
        delivery_state = "pending"
    elif classification["label"] != "bad" and previous_delivery == "pending":
        delivery_state = None
    else:
        delivery_state = previous_delivery
    conn.execute(
        """INSERT INTO ip_classification_state
           (ip,label,score,confidence,updated_at,last_alert_at,last_alert_label)
         VALUES (?,?,?,?,?,?,?)
           ON CONFLICT(ip) DO UPDATE SET label=excluded.label, score=excluded.score,
             confidence=excluded.confidence, updated_at=excluded.updated_at,
             last_alert_at=ip_classification_state.last_alert_at,
             last_alert_label=excluded.last_alert_label""",
        (ip, classification["label"], int(classification.get("score", 0)),
         int(classification.get("confidence", 0)), now.isoformat(),
         None, delivery_state),
    )
    return alert


def should_alert(previous, classification: dict, now: datetime) -> bool:
    """Current policy hook; additional alert rules can be added here later."""
    old_label = previous["label"] if previous else None
    delivery_state = previous["last_alert_label"] if previous else None
    last_alert = _parse(previous["last_alert_at"]) if previous else None
    cooldown_ok = not last_alert or (now - last_alert).total_seconds() >= cooldown_seconds()
    if classification["label"] != "bad" or delivery_state == "pending":
        return False
    if old_label == "bad" and delivery_state == "bad":
        return False
    return cooldown_ok


def _mark_alert_delivered(conn, ip: str, now: datetime) -> None:
    conn.execute(
        "UPDATE ip_classification_state SET last_alert_at=?, last_alert_label='bad' WHERE ip=?",
        (now.isoformat(), ip),
    )


def _clear_alert_pending(conn, ip: str) -> None:
    conn.execute(
        "UPDATE ip_classification_state SET last_alert_label=NULL WHERE ip=? AND last_alert_label='pending'",
        (ip,),
    )


async def run_classification_watcher(stop_event: asyncio.Event | None = None) -> None:
    stop_event = stop_event or asyncio.Event()
    conn = connect()
    try:
        cursor = _consumer_cursor(conn)
    finally:
        conn.close()
    while not stop_event.is_set():
        conn = connect()
        try:
            oldest_row = conn.execute("SELECT MIN(seq) AS seq FROM ip_change_log").fetchone()
            if oldest_row["seq"] and cursor and cursor < int(oldest_row["seq"]) - 1:
                cursor = int(oldest_row["seq"]) - 1
                _save_consumer_cursor(conn, cursor, "reset_required")
                conn.commit()
            rows = conn.execute(
                "SELECT seq, ip FROM ip_change_log WHERE seq>? ORDER BY seq LIMIT 500",
                (cursor,),
            ).fetchall()
            if rows:
                next_cursor = max(int(row["seq"]) for row in rows)
                for ip in dict.fromkeys(row["ip"] for row in rows):
                    classification, profile, observation = _classification_for_ip(conn, ip)
                    alert = _record_state(conn, ip, classification, _now())
                    if alert and telegram_enabled():
                        _enqueue_alert(conn, ip, format_bad_alert(ip, classification, profile, observation), _now())
                    elif alert:
                        _clear_alert_pending(conn, ip)
                _save_consumer_cursor(conn, next_cursor)
                conn.commit()
                cursor = next_cursor
        except Exception:
            conn.rollback()
            logger.exception("Classification watcher cycle failed")
        finally:
            conn.close()
        await _deliver_outbox()
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=WATCH_INTERVAL_SECONDS)
        except asyncio.TimeoutError:
            pass
