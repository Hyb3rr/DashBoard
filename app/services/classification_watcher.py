"""Background classification transition watcher."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import logging

from ..core.correlation import cluster_for_ip
from ..core.db import connect, decode, region_profile
from ..core.intelligence import classify_ip
from .profiles import ai_profile_for_ip, classification_observation, profile_from_row
from .telegram import cooldown_seconds, format_bad_alert, send_message

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


def _classification_for_ip(conn, ip: str):
    observation_row = conn.execute("SELECT * FROM ip_observations WHERE ip=?", (ip,)).fetchone()
    profile_row = conn.execute("SELECT * FROM ip_profiles WHERE ip=?", (ip,)).fetchone()
    observation = classification_observation(dict(observation_row)) if observation_row else {}
    if observation_row:
        observation["behavior_evidence"] = decode(observation_row["behavior_evidence_json"])
    profile = profile_from_row(profile_row) if profile_row else {"ip": ip}
    region = region_profile(conn, profile.get("country_code")) or {}
    ai_profile = ai_profile_for_ip(conn, ip)
    cluster = cluster_for_ip(conn, ip)
    classification = classify_ip(profile, observation, region, ai_profile, cluster)
    return classification, profile, observation


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
        cursor = _cursor(conn)
    finally:
        conn.close()
    while not stop_event.is_set():
        alerts = []
        conn = connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute(
                "SELECT seq, ip FROM ip_change_log WHERE seq>? ORDER BY seq",
                (cursor,),
            ).fetchall()
            if rows:
                next_cursor = max(int(row["seq"]) for row in rows)
                for ip in dict.fromkeys(row["ip"] for row in rows):
                    classification, profile, observation = _classification_for_ip(conn, ip)
                    if _record_state(conn, ip, classification, _now()):
                        alerts.append((ip, classification, profile, observation))
                conn.commit()
                cursor = next_cursor
        except Exception:
            conn.rollback()
            logger.exception("Classification watcher cycle failed")
        finally:
            conn.close()
        for ip, classification, profile, observation in alerts:
            async def deliver(ip=ip, classification=classification, profile=profile, observation=observation):
                delivered = await send_message(format_bad_alert(ip, classification, profile, observation))
                conn = connect()
                try:
                    if delivered:
                        _mark_alert_delivered(conn, ip, _now())
                    else:
                        _clear_alert_pending(conn, ip)
                    conn.commit()
                finally:
                    conn.close()
            asyncio.create_task(deliver())
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=WATCH_INTERVAL_SECONDS)
        except asyncio.TimeoutError:
            pass
