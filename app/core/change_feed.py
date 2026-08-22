"""Shared incremental IP change feed helpers — PostgreSQL only."""

from __future__ import annotations

from datetime import datetime, timezone


def append_ip_changes(conn, ips, reason: str, changed_at: str | None = None) -> int:
    """Insert ip_change_log rows for a batch of IPs (PG conn, %s placeholders)."""
    timestamp = changed_at or datetime.now(timezone.utc).isoformat()
    unique_ips = tuple(dict.fromkeys(ip for ip in ips if ip))
    if not unique_ips:
        return 0
    conn.executemany(
        "INSERT INTO ip_change_log (ip, reason, changed_at) VALUES (%s, %s, %s)",
        ((ip, reason, timestamp) for ip in unique_ips),
    )
    return len(unique_ips)


def append_classification_change(
    conn,
    ip: str,
    old_label: str | None,
    new_label: str,
    old_score: int | None,
    new_score: int,
    changed_at: str | None = None,
) -> None:
    """Insert a classification change row into ip_change_log."""
    timestamp = changed_at or datetime.now(timezone.utc).isoformat()
    conn.execute(
        """INSERT INTO ip_change_log
           (ip, reason, changed_at, old_label, new_label, old_score, new_score)
           VALUES (%s, 'classification', %s, %s, %s, %s, %s)""",
        (ip, timestamp, old_label, new_label, old_score, new_score),
    )
