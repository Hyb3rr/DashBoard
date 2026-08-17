"""Shared incremental IP change feed helpers."""

from __future__ import annotations

from datetime import datetime, timezone


def append_ip_changes(conn, ips, reason: str, changed_at: str | None = None) -> int:
    timestamp = changed_at or datetime.now(timezone.utc).isoformat()
    unique_ips = tuple(dict.fromkeys(ip for ip in ips if ip))
    conn.executemany(
        "INSERT INTO ip_change_log (ip, reason, changed_at) VALUES (?, ?, ?)",
        ((ip, reason, timestamp) for ip in unique_ips),
    )
    return len(unique_ips)
