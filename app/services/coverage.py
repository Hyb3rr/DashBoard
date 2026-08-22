"""Incremental detection/technique coverage consumer — PostgreSQL only."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import logging

from ..db import postgres as postgres_store
from ..core.rules import rules, ruleset_hash

logger = logging.getLogger(__name__)
CONSUMER_ID = "mitre_coverage"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _cursor(conn) -> int:
    row = conn.execute(
        "SELECT last_seq FROM change_consumer_state WHERE consumer_id=%s", (CONSUMER_ID,)
    ).fetchone()
    if row:
        return int(row["last_seq"])
    conn.execute(
        "INSERT INTO change_consumer_state(consumer_id,last_seq,updated_at,status) VALUES (%s,0,%s,'active')",
        (CONSUMER_ID, _now()),
    )
    return 0


def _record(conn, ip: str, window: str, seq: int) -> None:
    # Read detection snapshots from the PG observations payload
    row = conn.execute(
        "SELECT payload FROM ip_observations_state WHERE ip=%s", (ip,)
    ).fetchone()
    if not row:
        return
    import json
    payload = json.loads(row["payload"] or "{}") if isinstance(row["payload"], str) else (row["payload"] or {})
    suffix = "1h" if window == "1h" else "24h"
    detections = payload.get(f"detections_{suffix}", []) or []
    now = _now()
    active_hash = ruleset_hash()
    for detection in detections:
        rule_id = detection.get("id")
        if not rule_id:
            continue
        conn.execute(
            """INSERT INTO rule_firing_state
               (ip,rule_id,"window",ruleset_hash,first_fired_at,last_fired_at,last_seen_seq)
               VALUES (%s,%s,%s,%s,%s,%s,%s)
               ON CONFLICT(ip,rule_id,"window") DO UPDATE SET
                 ruleset_hash=EXCLUDED.ruleset_hash,last_fired_at=EXCLUDED.last_fired_at,
                 last_seen_seq=EXCLUDED.last_seen_seq""",
            (ip, rule_id, window, active_hash, now, now, seq),
        )


def process_once(limit: int = 500) -> dict:
    with postgres_store.transaction() as conn:
        cursor = _cursor(conn)
        oldest_row = conn.execute("SELECT MIN(seq) AS seq FROM ip_change_log").fetchone()
        oldest = oldest_row["seq"] if oldest_row else None
        status = "active"
        if oldest and cursor and cursor < int(oldest) - 1:
            status = "reset_required"
            cursor = int(oldest) - 1
        rows = conn.execute(
            "SELECT seq,ip FROM ip_change_log WHERE seq>%s ORDER BY seq LIMIT %s", (cursor, limit)
        ).fetchall()
        if not rows:
            conn.execute(
                "UPDATE change_consumer_state SET updated_at=%s,status=%s WHERE consumer_id=%s",
                (_now(), status, CONSUMER_ID),
            )
            return {"processed": 0, "cursor": cursor, "status": status}
        next_cursor = max(int(row["seq"]) for row in rows)
        for ip in dict.fromkeys(row["ip"] for row in rows):
            _record(conn, ip, "1h", next_cursor)
            _record(conn, ip, "24h", next_cursor)
        conn.execute(
            "UPDATE change_consumer_state SET last_seq=%s,updated_at=%s,status='active' WHERE consumer_id=%s",
            (next_cursor, _now(), CONSUMER_ID),
        )
        return {"processed": len(rows), "cursor": next_cursor, "status": status}


def coverage_matrix(window: str = "24h") -> list[dict]:
    if window not in {"1h", "24h"}:
        raise ValueError("window must be 1h or 24h")
    cutoff = datetime.now(timezone.utc) - timedelta(hours=1 if window == "1h" else 24)
    result = []
    active_hash = ruleset_hash()
    with postgres_store.transaction() as conn:
        for rule in rules():
            if rule.window != window:
                continue
            row = conn.execute(
                "SELECT COUNT(*) AS n, MAX(last_fired_at) AS last_fired_at FROM rule_firing_state WHERE rule_id=%s AND \"window\"=%s AND ruleset_hash=%s",
                (rule.id, window, active_hash),
            ).fetchone()
            last = row["last_fired_at"] if row else None
            recent = False
            if last:
                try:
                    ts = last if hasattr(last, "tzinfo") else datetime.fromisoformat(str(last).replace("Z", "+00:00"))
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=timezone.utc)
                    recent = ts >= cutoff
                except (ValueError, AttributeError):
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
                "last_fired_at": str(last) if last else None,
                "ruleset_hash": active_hash,
            })
    return result


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
