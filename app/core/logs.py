"""Apache log parsing and behavior-scoring helpers.

All DB persistence is handled by PgDetectionRepository (PostgreSQL) and
ClickHouse. This module is now a pure parser with no database dependency.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timezone
import hashlib
import ipaddress
import re

from .json_utils import encode  # kept for callers that use encode/decode from here

APACHE_COMBINED = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) [^"]+" '
    r'(?P<status>\d{3}) (?P<bytes>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<ua>[^"]*)"(?: "[^"]*")?$'
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


def import_apache_lines(lines: Iterable[str], source: str) -> dict:
    """Parse Apache log lines and return a list of parsed event dicts.

    This is a pure function — no DB writes. Callers are responsible for
    persisting the returned events via PgDetectionRepository or similar.
    """
    parsed_events: list[dict] = []
    parsed = 0
    skipped = 0
    now = datetime.now(timezone.utc).isoformat()
    offset = 0
    for line in lines:
        raw = line.rstrip("\n")
        line_offset = offset
        offset += len(line.encode("utf-8"))
        if not raw:
            continue
        event = parse_apache_combined(raw)
        if not event:
            skipped += 1
            continue
        parsed += 1
        line_hash = hashlib.sha256(f"{source}\0{line_offset}\0{raw}".encode()).hexdigest()
        parsed_events.append({
            **event,
            "source": source,
            "line_hash": line_hash,
            "source_offset": line_offset,
            "raw_line": raw,
            "ingested_at": now,
        })
    return {
        "events": parsed_events,
        "parsed": parsed,
        "skipped": skipped,
    }


def effective_risk(profile_score: int | None, behavior_score: int | None) -> tuple[int, str]:
    score = min((profile_score or 0) + (behavior_score or 0), 100)
    level = "low" if score < 25 else "medium" if score < 55 else "high" if score < 80 else "critical"
    return score, level
