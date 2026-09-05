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

__all__ = [
    "encode",
    "PARSER_VERSION",
    "parse_apache_combined",
    "parse_apache_combined_diagnostic",
    "import_apache_lines",
    "effective_risk",
]

PARSER_VERSION = "apache-combined-v1"

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
    event, _code, _message = parse_apache_combined_diagnostic(line)
    return event


def parse_apache_combined_diagnostic(line: str) -> tuple[dict | None, str | None, str | None]:
    match = APACHE_COMBINED.match(line.strip())
    if not match:
        return None, "INVALID_APACHE_COMBINED_FORMAT", "line does not match Apache Combined format"
    data = match.groupdict()
    try:
        ip = str(ipaddress.ip_address(data["ip"]))
    except ValueError:
        return None, "INVALID_IP", "source IP is not a valid address"
    timestamp = _parse_ts(data["ts"])
    if timestamp is None:
        return None, "INVALID_TIMESTAMP", "timestamp is not a valid Apache timestamp"
    try:
        bytes_sent = None if data["bytes"] == "-" else int(data["bytes"])
    except ValueError:
        return None, "INVALID_BYTE_COUNT", "byte count is not numeric"
    return {
        "src_ip": ip,
        "timestamp": timestamp,
        "method": data["method"],
        "path": data["path"],
        "status": int(data["status"]),
        "bytes_sent": bytes_sent,
        "referer": None if data["referer"] == "-" else data["referer"],
        "user_agent": None if data["ua"] == "-" else data["ua"],
    }, None, None


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
