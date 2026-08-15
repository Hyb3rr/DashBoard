"""Incremental detection/technique coverage consumer."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import logging

from ..core.db import connect
from ..core.rules import rules, ruleset_hash
from .classification import detection_snapshot

logger = logging.getLogger(__name__)
CONSUMER_ID = "mitre_coverage"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _cursor(conn) -> int:
    row = conn.execute("SELECT last_seq FROM change_consumer_state WHERE consumer_id=?", (CONSUMER_ID,)).fetchone()
    if row:
        return int(row["last_seq"])
    # Coverage is safe to backfill from the beginning; unlike Telegram it has
    # no alert side effects and must not miss historical firings on first start.
    current = 0
    conn.execute("INSERT INTO change_consumer_state(consumer_id,last_seq,updated_at,status) VALUES (?,?,?,'active')", (CONSUMER_ID, current, _now()))
    conn.commit()
    return current


def _record(conn, ip: str, window: str, seq: int) -> None:
    snapshot = detection_snapshot(conn, ip, window)
    now = _now()
    for detection in snapshot["detections"]:
        rule_id = detection.get("id")
        if not rule_id:
            continue
        conn.execute(
            """INSERT INTO rule_firing_state
               (ip,rule_id,window,ruleset_hash,first_fired_at,last_fired_at,last_seen_seq)
               VALUES (?,?,?,?,?,?,?)
               ON CONFLICT(ip,rule_id,window) DO UPDATE SET
                 ruleset_hash=excluded.ruleset_hash,last_fired_at=excluded.last_fired_at,
                 last_seen_seq=excluded.last_seen_seq""",
            (ip, rule_id, window, snapshot["ruleset_hash"] or ruleset_hash(), now, now, seq),
        )


def process_once(limit: int = 500) -> dict:
    conn = connect()
    try:
        cursor = _cursor(conn)
        oldest = conn.execute("SELECT MIN(seq) AS seq FROM ip_change_log").fetchone()["seq"]
        status = "active"
        if oldest and cursor and cursor < int(oldest) - 1:
            status = "reset_required"
            cursor = int(oldest) - 1
        rows = conn.execute("SELECT seq,ip FROM ip_change_log WHERE seq>? ORDER BY seq LIMIT ?", (cursor, limit)).fetchall()
        if not rows:
            conn.execute("UPDATE change_consumer_state SET updated_at=?,status=? WHERE consumer_id=?", (_now(), status, CONSUMER_ID))
            conn.commit()
            return {"processed": 0, "cursor": cursor, "status": status}
        next_cursor = max(int(row["seq"]) for row in rows)
        for ip in dict.fromkeys(row["ip"] for row in rows):
            _record(conn, ip, "1h", next_cursor)
            _record(conn, ip, "24h", next_cursor)
        conn.execute("UPDATE change_consumer_state SET last_seq=?,updated_at=?,status='active' WHERE consumer_id=?", (next_cursor, _now(), CONSUMER_ID))
        conn.commit()
        return {"processed": len(rows), "cursor": next_cursor, "status": status}
    finally:
        conn.close()


def coverage_matrix(window: str = "24h") -> list[dict]:
    if window not in {"1h", "24h"}:
        raise ValueError("window must be 1h or 24h")
    conn = connect()
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=1 if window == "1h" else 24)
        result = []
        for rule in rules():
            row = conn.execute(
                "SELECT COUNT(*) AS n, MAX(last_fired_at) AS last_fired_at FROM rule_firing_state WHERE rule_id=? AND window=?",
                (rule.id, window),
            ).fetchone()
            last = row["last_fired_at"]
            recent = False
            if last:
                try:
                    recent = datetime.fromisoformat(last.replace("Z", "+00:00")) >= cutoff
                except ValueError:
                    recent = False
            result.append({
                "rule_id": rule.id,
                "name": rule.name,
                "rule_type": rule.rule_type,
                "window": rule.window,
                "mitre_technique": rule.mitre_technique,
                "implemented": True,
                "validated": True,
                "telemetry_ready": True,
                "recently_observed": recent,
                "last_fired_at": last,
                "ruleset_hash": ruleset_hash(),
            })
        return result
    finally:
        conn.close()


async def run_coverage_consumer(stop_event: asyncio.Event | None = None) -> None:
    stop_event = stop_event or asyncio.Event()
    while not stop_event.is_set():
        try:
            await asyncio.to_thread(process_once)
        except Exception:
            logger.exception("Coverage consumer cycle failed")
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=5)
        except asyncio.TimeoutError:
            pass
