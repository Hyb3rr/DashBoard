"""AI feature extraction — pure Python, no database dependency.

build_window_features() now accepts pre-fetched bucket rows as plain dicts
instead of a SQLite connection. The caller (PgDetectionRepository or
score_cycle) is responsible for fetching the rows from PostgreSQL.
"""

from __future__ import annotations

from datetime import datetime
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
    bucket_rows: Sequence[dict],
) -> pd.DataFrame:
    """Build one row per IP/minute from pre-fetched PG bucket rows.

    Each row dict must have: ip, bucket_minute, requests, unique_paths_approx,
    status_404, status_403, status_5xx, post_requests, sensitive_hits,
    wp_login_hits, bytes_sum.
    """
    if not bucket_rows:
        return _empty()

    grouped = []
    for row in bucket_rows:
        requests = int(row.get("requests") or 0)
        grouped.append({
            "ip": row["ip"],
            "window_start": pd.Timestamp(str(row["bucket_minute"])),
            "requests": requests,
            "unique_paths": int(row.get("unique_paths_approx") or 0),
            "ratio_404": int(row.get("status_404") or 0) / requests if requests else 0.0,
            "ratio_403": int(row.get("status_403") or 0) / requests if requests else 0.0,
            "ratio_5xx": int(row.get("status_5xx") or 0) / requests if requests else 0.0,
            "post_ratio": int(row.get("post_requests") or 0) / requests if requests else 0.0,
            "sensitive_hits": int(row.get("sensitive_hits") or 0),
            "login_attempts": int(row.get("wp_login_hits") or 0),
            "avg_request_interval": 0.0,
            "std_request_interval": 0.0,
            "unique_user_agents": 0,
            "bytes_avg": int(row.get("bytes_sum") or 0) / requests if requests else 0.0,
        })
    return pd.DataFrame(grouped, columns=WINDOW_COLUMNS)


def build_window_features_from_events(
    events: Sequence[dict],
    start_at: datetime | str | None = None,
    end_at: datetime | str | None = None,
    ips: Sequence[str] | None = None,
) -> pd.DataFrame:
    """Build window features directly from raw event dicts (for testing/replay)."""
    if not events:
        return _empty()

    frame = pd.DataFrame(events)
    if "timestamp" not in frame.columns or "src_ip" not in frame.columns:
        return _empty()

    frame["timestamp"] = pd.to_datetime(frame["timestamp"], utc=True, errors="coerce")
    frame = frame.dropna(subset=["timestamp", "src_ip"])
    if frame.empty:
        return _empty()

    if start_at is not None:
        start_ts = pd.Timestamp(start_at if isinstance(start_at, str) else start_at.isoformat(), tz="UTC")
        frame = frame[frame["timestamp"] >= start_ts]
    if end_at is not None:
        end_ts = pd.Timestamp(end_at if isinstance(end_at, str) else end_at.isoformat(), tz="UTC")
        frame = frame[frame["timestamp"] < end_ts]
    if ips is not None:
        frame = frame[frame["src_ip"].isin(set(ips))]
    if frame.empty:
        return _empty()

    frame["window_start"] = frame["timestamp"].dt.floor("1min")
    frame["path_text"] = frame.get("path", pd.Series(dtype=str)).fillna("").astype(str).str.lower()
    frame["method_text"] = frame.get("method", pd.Series(dtype=str)).fillna("").astype(str).str.upper()
    frame["user_agent_text"] = frame.get("user_agent", pd.Series(dtype=str)).fillna("").astype(str)
    frame["status_num"] = pd.to_numeric(frame.get("status", pd.Series(dtype=int)), errors="coerce").fillna(0)
    frame["bytes_num"] = pd.to_numeric(frame.get("bytes_sent", pd.Series(dtype=int)), errors="coerce")
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
