import json
import sqlite3
import threading
from pathlib import Path

from ..config.settings import DB_PATH, REGION_SEED_PATH
from .regions import market_score, normalise_conflict_indicators, normalise_economic_indicators


SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source TEXT NOT NULL,
  line_hash TEXT NOT NULL UNIQUE,
  raw_line TEXT NOT NULL,
  timestamp TEXT,
  src_ip TEXT NOT NULL,
  method TEXT,
  path TEXT,
  status INTEGER,
  bytes_sent INTEGER,
  referer TEXT,
  user_agent TEXT,
  imported_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);

CREATE TABLE IF NOT EXISTS ip_profiles (
  ip TEXT PRIMARY KEY, country TEXT, country_code TEXT, city TEXT, region TEXT,
  latitude REAL, longitude REAL, timezone TEXT, asn TEXT, organization TEXT, isp TEXT,
  network_type TEXT, ip_prefix TEXT,
  organization_confidence INTEGER NOT NULL DEFAULT 0,
  identity_evidence_json TEXT NOT NULL DEFAULT '[]',
  is_hosting INTEGER, is_vpn INTEGER, is_proxy INTEGER, is_tor INTEGER,
  abuse_score INTEGER, abuse_reports INTEGER, reputation_json TEXT NOT NULL DEFAULT '[]',
  enrichment_status TEXT NOT NULL DEFAULT 'partial',
  core_enrichment_status TEXT NOT NULL DEFAULT 'partial',
  privacy_enrichment_status TEXT NOT NULL DEFAULT 'unknown',
  threat_enrichment_status TEXT NOT NULL DEFAULT 'unknown',
  provider_errors_json TEXT NOT NULL DEFAULT '[]',
  provider_status_json TEXT NOT NULL DEFAULT '{}',
  field_sources_json TEXT NOT NULL DEFAULT '{}',
  next_retry_at TEXT, enrichment_attempts INTEGER NOT NULL DEFAULT 0,
  risk_score INTEGER NOT NULL DEFAULT 0, risk_level TEXT NOT NULL DEFAULT 'unknown',
  evidence_json TEXT NOT NULL DEFAULT '[]', source_json TEXT NOT NULL DEFAULT '[]',
  fetched_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ip_observations (
  ip TEXT PRIMARY KEY,
  first_seen TEXT,
  last_seen TEXT,
  requests INTEGER NOT NULL DEFAULT 0,
  status_2xx INTEGER NOT NULL DEFAULT 0,
  status_3xx INTEGER NOT NULL DEFAULT 0,
  status_4xx INTEGER NOT NULL DEFAULT 0,
  status_5xx INTEGER NOT NULL DEFAULT 0,
  unique_paths INTEGER NOT NULL DEFAULT 0,
  wp_login_requests INTEGER NOT NULL DEFAULT 0,
  sensitive_probe_requests INTEGER NOT NULL DEFAULT 0,
  bot_requests INTEGER NOT NULL DEFAULT 0,
  behavior_score INTEGER NOT NULL DEFAULT 0,
  behavior_level TEXT NOT NULL DEFAULT 'low',
  behavior_evidence_json TEXT NOT NULL DEFAULT '[]',
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ip_ai_scores (
  ip TEXT PRIMARY KEY,
  windows_seen INTEGER NOT NULL,
  anomalous_windows INTEGER NOT NULL,
  ai_anomaly_score INTEGER NOT NULL,
  ai_evidence_json TEXT NOT NULL DEFAULT '[]',
  model_mode TEXT NOT NULL,
  scored_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS region_profiles (
  country_code TEXT PRIMARY KEY, country_name TEXT, economic_indicators_json TEXT,
  cultural_context_json TEXT, conflict_indicators_json TEXT, sources_json TEXT,
  observed_ip_count INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL
);
"""

_seed_lock = threading.RLock()
_seed_cache: dict[tuple[str, str], tuple[int, int]] = {}

IP_PROFILE_COLUMNS = {
    "timezone": "TEXT",
    "network_type": "TEXT",
    "ip_prefix": "TEXT",
    "organization_confidence": "INTEGER NOT NULL DEFAULT 0",
    "identity_evidence_json": "TEXT NOT NULL DEFAULT '[]'",
    "abuse_score": "INTEGER",
    "abuse_reports": "INTEGER",
    "reputation_json": "TEXT NOT NULL DEFAULT '[]'",
    "enrichment_status": "TEXT NOT NULL DEFAULT 'partial'",
    "core_enrichment_status": "TEXT NOT NULL DEFAULT 'partial'",
    "privacy_enrichment_status": "TEXT NOT NULL DEFAULT 'unknown'",
    "threat_enrichment_status": "TEXT NOT NULL DEFAULT 'unknown'",
    "provider_errors_json": "TEXT NOT NULL DEFAULT '[]'",
    "provider_status_json": "TEXT NOT NULL DEFAULT '{}'",
    "field_sources_json": "TEXT NOT NULL DEFAULT '{}'",
    "next_retry_at": "TEXT",
    "enrichment_attempts": "INTEGER NOT NULL DEFAULT 0",
}

def _migrate(conn: sqlite3.Connection) -> None:
    existing = {row["name"] for row in conn.execute("PRAGMA table_info(ip_profiles)").fetchall()}
    for column, definition in IP_PROFILE_COLUMNS.items():
        if column not in existing:
            conn.execute(f"ALTER TABLE ip_profiles ADD COLUMN {column} {definition}")


def _seed_region_profiles(conn: sqlite3.Connection) -> None:
    if not REGION_SEED_PATH.exists():
        return
    with _seed_lock:
        try:
            stat = REGION_SEED_PATH.stat()
            signature = (stat.st_mtime_ns, stat.st_size)
            cache_key = (str(REGION_SEED_PATH.resolve()), str(DB_PATH.resolve()))
            existing = conn.execute("SELECT COUNT(*) AS n FROM region_profiles").fetchone()
            if _seed_cache.get(cache_key) == signature and existing and existing["n"]:
                return
            payload = json.loads(REGION_SEED_PATH.read_text(encoding="utf-8"))
            if not isinstance(payload, list):
                raise ValueError("region seed must be a JSON array")
            for item in payload:
                if not item.get("country_code") or not item.get("country_name"):
                    raise ValueError("region seed item missing country identity")
                conn.execute(
                    """
                    INSERT OR REPLACE INTO region_profiles
                      (country_code,country_name,economic_indicators_json,cultural_context_json,
                       conflict_indicators_json,sources_json,observed_ip_count,updated_at)
                    VALUES (?,?,?,?,?,?,COALESCE((SELECT observed_ip_count FROM region_profiles WHERE country_code = ?), 0),?)
                    """,
                    (
                        item["country_code"],
                        item["country_name"],
                        encode(normalise_economic_indicators(item.get("economic_indicators"))),
                        encode(item.get("cultural_context")),
                        encode(normalise_conflict_indicators(item.get("conflict_indicators"))),
                        encode(item.get("sources")),
                        item["country_code"],
                        item.get("updated_at") or "",
                    ),
                )
            conn.commit()
            _seed_cache[cache_key] = signature
        except (OSError, json.JSONDecodeError, ValueError, sqlite3.Error):
            conn.rollback()


def region_profile(conn: sqlite3.Connection, country_code: str | None):
    if not country_code:
        return None
    row = conn.execute("SELECT * FROM region_profiles WHERE country_code = ?", (country_code,)).fetchone()
    if not row:
        return None
    data = dict(row)
    data["economic_indicators"] = normalise_economic_indicators(decode(data.pop("economic_indicators_json")))
    data["cultural_context"] = decode(data.pop("cultural_context_json"))
    data["conflict_indicators"] = normalise_conflict_indicators(decode(data.pop("conflict_indicators_json")))
    data["sources"] = decode(data.pop("sources_json"))
    observed = conn.execute("SELECT COUNT(*) AS n FROM ip_profiles WHERE country_code = ?", (country_code,)).fetchone()
    data["observed_ip_count"] = observed["n"] if observed else data.get("observed_ip_count", 0)
    data.update(market_score(data))
    return data

def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    # WAL: writers don't block readers and each commit no longer needs a full
    # fsync of the rollback journal. synchronous=NORMAL is safe under WAL
    # (durable across app crashes, only a very unlikely OS-crash-at-the-wrong-
    # instant could lose the last few commits) and is dramatically faster when
    # committing one row at a time, which is exactly the mapping workload here.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.executescript(SCHEMA)
    _migrate(conn)
    _seed_region_profiles(conn)
    conn.commit()
    return conn

def encode(value):
    return json.dumps([] if value is None else value, ensure_ascii=False)

def decode(value):
    try:
        return json.loads(value or "[]")
    except json.JSONDecodeError:
        return []
