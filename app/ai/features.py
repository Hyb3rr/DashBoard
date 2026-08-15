from __future__ import annotations

from datetime import datetime
import sqlite3
from collections.abc import Sequence

import pandas as pd


FEATURE_COLUMNS = [
    "requests",
    "unique_paths",
    "ratio_404",
    "ratio_403",
    "ratio_5xx",
    "post_ratio",
    "sensitive_hits",
    "login_attempts",
    "avg_request_interval",
    "std_request_interval",
    "unique_user_agents",
    "bytes_avg",
]

WINDOW_COLUMNS = ["ip", "window_start", *FEATURE_COLUMNS]
SENSITIVE_MARKERS = (
    "/.env", "/.git", "wp-config.php", "xmlrpc.php",
    "phpmyadmin", "adminer", "vendor/phpunit",
)


def _empty() -> pd.DataFrame:
    return pd.DataFrame(columns=WINDOW_COLUMNS)


def build_window_features(
    conn: sqlite3.Connection,
    start_at: datetime | str | None = None,
    end_at: datetime | str | None = None,
    ips: Sequence[str] | None = None,
) -> pd.DataFrame:
    """Build one row per IP/minute inside a bounded UTC event-time range."""
    bucket_where = []
    bucket_params: list[object] = []
    if start_at is not None and end_at is not None:
        bucket_where.extend(["bucket_minute >= ?", "bucket_minute < ?"])
        bucket_params.extend([
            start_at.isoformat() if isinstance(start_at, datetime) else start_at,
            end_at.isoformat() if isinstance(end_at, datetime) else end_at,
        ])
    if ips is not None:
        unique_ips = tuple(dict.fromkeys(ips))
        if not unique_ips:
            return _empty()
        bucket_where.append("ip IN (" + ",".join("?" for _ in unique_ips) + ")")
        bucket_params.extend(unique_ips)
    bucket_clause = " WHERE " + " AND ".join(bucket_where) if bucket_where else ""
    bucket_rows = conn.execute(
        "SELECT * FROM ip_time_buckets" + bucket_clause + " ORDER BY ip, bucket_minute", bucket_params
    ).fetchall()
    if bucket_rows:
        grouped = []
        for row in bucket_rows:
            requests = int(row["requests"] or 0)
            grouped.append({
                "ip": row["ip"],
                "window_start": pd.Timestamp(row["bucket_minute"]),
                "requests": requests,
                "unique_paths": int(row["unique_paths_approx"] or 0),
                "ratio_404": int(row["status_404"] or 0) / requests if requests else 0.0,
                "ratio_403": int(row["status_403"] or 0) / requests if requests else 0.0,
                "ratio_5xx": int(row["status_5xx"] or 0) / requests if requests else 0.0,
                "post_ratio": int(row["post_requests"] or 0) / requests if requests else 0.0,
                "sensitive_hits": int(row["sensitive_hits"] or 0),
                "login_attempts": int(row["wp_login_hits"] or 0),
                # Inter-arrival and user-agent cardinality are intentionally
                # neutral until their own persisted aggregates are added.
                "avg_request_interval": 0.0,
                "std_request_interval": 0.0,
                "unique_user_agents": 0,
                "bytes_avg": int(row["bytes_sum"] or 0) / requests if requests else 0.0,
            })
        return pd.DataFrame(grouped, columns=WINDOW_COLUMNS)

    if start_at is None or end_at is None:
        bounds = conn.execute("SELECT MIN(timestamp) AS start_at, MAX(timestamp) AS end_at FROM events WHERE timestamp IS NOT NULL").fetchone()
        if not bounds or not bounds["start_at"] or not bounds["end_at"]:
            return _empty()
        start_at, end_at = bounds["start_at"], bounds["end_at"] + "\uffff"
    where = "timestamp IS NOT NULL AND timestamp >= ? AND timestamp < ?"
    params: list[object] = [start_at.isoformat() if isinstance(start_at, datetime) else start_at,
                            end_at.isoformat() if isinstance(end_at, datetime) else end_at]
    if ips is not None:
        unique_ips = tuple(dict.fromkeys(ips))
        if not unique_ips:
            return _empty()
        placeholders = ",".join("?" for _ in unique_ips)
        where += f" AND src_ip IN ({placeholders})"
        params.extend(unique_ips)
    rows = conn.execute(
        f"""
        SELECT timestamp, src_ip, method, path, status, bytes_sent, user_agent
        FROM events
        WHERE {where}
        """,
        params,
    ).fetchall()
    if not rows:
        return _empty()

    frame = pd.DataFrame([dict(row) for row in rows])
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], utc=True, errors="coerce")
    frame = frame.dropna(subset=["timestamp", "src_ip"])
    if frame.empty:
        return _empty()

    frame["window_start"] = frame["timestamp"].dt.floor("1min")
    frame["path_text"] = frame["path"].fillna("").astype(str).str.lower()
    frame["method_text"] = frame["method"].fillna("").astype(str).str.upper()
    frame["user_agent_text"] = frame["user_agent"].fillna("").astype(str)
    frame["status_num"] = pd.to_numeric(frame["status"], errors="coerce").fillna(0)
    frame["bytes_num"] = pd.to_numeric(frame["bytes_sent"], errors="coerce")
    frame["is_404"] = (frame["status_num"] == 404).astype(int)
    frame["is_403"] = (frame["status_num"] == 403).astype(int)
    frame["is_5xx"] = (frame["status_num"] >= 500).astype(int)
    frame["is_post"] = (frame["method_text"] == "POST").astype(int)
    frame["sensitive"] = frame["path_text"].map(
        lambda path: int(any(marker in path for marker in SENSITIVE_MARKERS))
    )
    frame["login"] = frame["path_text"].str.contains("/wp-login.php", regex=False).astype(int)

    grouped = []
    for (ip, window_start), group in frame.groupby(["src_ip", "window_start"], sort=True):
        timestamps = group["timestamp"].sort_values().astype("int64") / 1_000_000_000
        intervals = timestamps.diff().dropna()
        grouped.append({
            "ip": ip,
            "window_start": window_start,
            "requests": int(len(group)),
            "unique_paths": int(group["path_text"].nunique()),
            "ratio_404": float(group["is_404"].mean()),
            "ratio_403": float(group["is_403"].mean()),
            "ratio_5xx": float(group["is_5xx"].mean()),
            "post_ratio": float(group["is_post"].mean()),
            "sensitive_hits": int(group["sensitive"].sum()),
            "login_attempts": int(group["login"].sum()),
            "avg_request_interval": float(intervals.mean()) if len(intervals) else 0.0,
            "std_request_interval": float(intervals.std(ddof=0)) if len(intervals) else 0.0,
            "unique_user_agents": int(group["user_agent_text"].nunique()),
            "bytes_avg": float(group["bytes_num"].mean()) if group["bytes_num"].notna().any() else 0.0,
        })
    return pd.DataFrame(grouped, columns=WINDOW_COLUMNS)
