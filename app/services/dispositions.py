"""Analyst-owned triage state, deliberately separate from classification."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import sqlite3

STATES = {"new", "monitor", "investigate", "escalate", "resolved"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def recommendation(label: str | None) -> str | None:
    return {"bad": "investigate", "watch": "monitor"}.get(label)


def _decode(value):
    try:
        return json.loads(value or "[]")
    except json.JSONDecodeError:
        return []


def ensure_disposition(conn: sqlite3.Connection, ip: str, label: str | None = None) -> dict:
    now = _now()
    suggestion = recommendation(label)
    conn.execute(
        """INSERT INTO ip_dispositions(ip, state, suggested_state, updated_at, history_json)
           VALUES (?, 'new', ?, ?, '[]')
           ON CONFLICT(ip) DO UPDATE SET suggested_state=excluded.suggested_state""",
        (ip, suggestion, now),
    )
    row = conn.execute("SELECT * FROM ip_dispositions WHERE ip=?", (ip,)).fetchone()
    conn.commit()
    item = dict(row)
    item["history"] = _decode(item.pop("history_json"))
    return item


def set_disposition(conn: sqlite3.Connection, ip: str, state: str, assigned_to: str | None = None,
                    note: str | None = None, actor: str = "system", label: str | None = None) -> dict:
    if state not in STATES:
        raise ValueError("invalid disposition state")
    current = ensure_disposition(conn, ip, label)
    now = _now()
    history = current["history"]
    history.append({
        "at": now, "actor": actor or "system", "from": current["state"], "to": state,
        "assigned_to": assigned_to, "note": note,
    })
    conn.execute(
        """UPDATE ip_dispositions SET state=?, assigned_to=?, note=?, updated_at=?, history_json=? WHERE ip=?""",
        (state, assigned_to, note, now, json.dumps(history, ensure_ascii=False), ip),
    )
    conn.commit()
    return ensure_disposition(conn, ip, label)
