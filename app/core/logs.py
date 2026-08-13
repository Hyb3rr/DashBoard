from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timezone
import hashlib
import ipaddress
import re
import sqlite3

from .db import encode
from ..ai.detector import score_import

APACHE_COMBINED = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) [^"]+" '
    r'(?P<status>\d{3}) (?P<bytes>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<ua>[^"]*)"$'
)

BOT_WORDS = ("bot", "spider", "crawler", "feedfetcher", "archive.org_bot")
SENSITIVE_PATHS = (
    "/.env",
    "/.git",
    "/wp-config.php",
    "/xmlrpc.php",
    "/phpmyadmin",
    "/adminer",
    "/vendor/phpunit",
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_ts(value: str) -> str | None:
    try:
        return datetime.strptime(value, "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc).isoformat()
    except ValueError:
        return None


def parse_apache_combined(line: str) -> dict | None:
    match = APACHE_COMBINED.match(line.strip())
    if not match:
        return None
    data = match.groupdict()
    try:
        ip = str(ipaddress.ip_address(data["ip"]))
    except ValueError:
        return None
    return {
        "src_ip": ip,
        "timestamp": _parse_ts(data["ts"]),
        "method": data["method"],
        "path": data["path"],
        "status": int(data["status"]),
        "bytes_sent": None if data["bytes"] == "-" else int(data["bytes"]),
        "referer": None if data["referer"] == "-" else data["referer"],
        "user_agent": None if data["ua"] == "-" else data["ua"],
    }


def _behavior_risk(row: sqlite3.Row) -> tuple[int, str, list[str]]:
    score = 0
    evidence: list[str] = []
    requests = row["requests"] or 0
    if row["sensitive_probe_requests"] > 0:
        score += 50
        evidence.append("Sensitive path probing (+50)")
    if row["wp_login_requests"] > 20:
        score += 30
        evidence.append("wp-login burst (+30)")
    if requests >= 20 and (row["status_4xx"] / requests) > 0.5:
        score += 15
        evidence.append("4xx ratio above 50% (+15)")
    if row["unique_paths"] > 80:
        score += 15
        evidence.append("High unique path count (+15)")
    if row["bot_requests"] and row["status_4xx"] > 10:
        score += 10
        evidence.append("Bot with repeated errors")
    score = min(score, 100)
    level = "low" if score < 25 else "medium" if score < 55 else "high" if score < 80 else "critical"
    return score, level, evidence


def rebuild_observations(conn: sqlite3.Connection) -> None:
    rows = conn.execute(
        """
        SELECT
          src_ip AS ip,
          MIN(timestamp) AS first_seen,
          MAX(timestamp) AS last_seen,
          COUNT(*) AS requests,
          SUM(CASE WHEN status BETWEEN 200 AND 299 THEN 1 ELSE 0 END) AS status_2xx,
          SUM(CASE WHEN status BETWEEN 300 AND 399 THEN 1 ELSE 0 END) AS status_3xx,
          SUM(CASE WHEN status BETWEEN 400 AND 499 THEN 1 ELSE 0 END) AS status_4xx,
          SUM(CASE WHEN status >= 500 THEN 1 ELSE 0 END) AS status_5xx,
          COUNT(DISTINCT path) AS unique_paths,
          SUM(CASE WHEN path LIKE '%/wp-login.php%' THEN 1 ELSE 0 END) AS wp_login_requests,
          SUM(CASE
            WHEN path LIKE '/.env%' OR path LIKE '/.git%' OR path LIKE '%wp-config.php%'
              OR path LIKE '%xmlrpc.php%' OR path LIKE '%phpmyadmin%'
              OR path LIKE '%adminer%' OR path LIKE '%vendor/phpunit%'
            THEN 1 ELSE 0 END) AS sensitive_probe_requests,
          SUM(CASE
            WHEN lower(COALESCE(user_agent, '')) LIKE '%bot%'
              OR lower(COALESCE(user_agent, '')) LIKE '%spider%'
              OR lower(COALESCE(user_agent, '')) LIKE '%crawler%'
              OR lower(COALESCE(user_agent, '')) LIKE '%feedfetcher%'
              OR lower(COALESCE(user_agent, '')) LIKE '%archive.org_bot%'
            THEN 1 ELSE 0 END) AS bot_requests
        FROM events
        GROUP BY src_ip
        """
    ).fetchall()
    now = _now()
    for row in rows:
        score, level, evidence = _behavior_risk(row)
        conn.execute(
            """
            INSERT OR REPLACE INTO ip_observations
              (ip,first_seen,last_seen,requests,status_2xx,status_3xx,status_4xx,status_5xx,
               unique_paths,wp_login_requests,sensitive_probe_requests,bot_requests,
               behavior_score,behavior_level,behavior_evidence_json,updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                row["ip"],
                row["first_seen"],
                row["last_seen"],
                row["requests"],
                row["status_2xx"] or 0,
                row["status_3xx"] or 0,
                row["status_4xx"] or 0,
                row["status_5xx"] or 0,
                row["unique_paths"] or 0,
                row["wp_login_requests"] or 0,
                row["sensitive_probe_requests"] or 0,
                row["bot_requests"] or 0,
                score,
                level,
                encode(evidence),
                now,
            ),
        )


def import_apache_lines(conn: sqlite3.Connection, lines: Iterable[str], source: str) -> dict:
    parsed = 0
    inserted = 0
    skipped = 0
    now = _now()
    for line in lines:
        raw = line.rstrip("\n")
        if not raw:
            continue
        event = parse_apache_combined(raw)
        if not event:
            skipped += 1
            continue
        parsed += 1
        line_hash = hashlib.sha256(f"{source}\0{raw}".encode()).hexdigest()
        cur = conn.execute(
            """
            INSERT OR IGNORE INTO events
              (source,line_hash,raw_line,timestamp,src_ip,method,path,status,bytes_sent,referer,user_agent,imported_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                source,
                line_hash,
                raw,
                event["timestamp"],
                event["src_ip"],
                event["method"],
                event["path"],
                event["status"],
                event["bytes_sent"],
                event["referer"],
                event["user_agent"],
                now,
            ),
        )
        inserted += cur.rowcount
    rebuild_observations(conn)
    result = {"parsed": parsed, "inserted": inserted, "duplicates": parsed - inserted, "skipped": skipped}
    result["ai_scoring"] = score_import(conn)
    return result


def effective_risk(profile_score: int | None, behavior_score: int | None) -> tuple[int, str]:
    score = min((profile_score or 0) + (behavior_score or 0), 100)
    level = "low" if score < 25 else "medium" if score < 55 else "high" if score < 80 else "critical"
    return score, level
