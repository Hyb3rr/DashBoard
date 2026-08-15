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
  source_offset INTEGER,
  imported_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_src_ip_timestamp ON events(src_ip, timestamp);

CREATE TABLE IF NOT EXISTS ip_time_buckets (
  ip TEXT NOT NULL,
  bucket_minute TEXT NOT NULL,
  requests INTEGER NOT NULL DEFAULT 0,
  status_2xx INTEGER NOT NULL DEFAULT 0,
  status_3xx INTEGER NOT NULL DEFAULT 0,
  status_4xx INTEGER NOT NULL DEFAULT 0,
  status_5xx INTEGER NOT NULL DEFAULT 0,
  status_403 INTEGER NOT NULL DEFAULT 0,
  status_404 INTEGER NOT NULL DEFAULT 0,
  post_requests INTEGER NOT NULL DEFAULT 0,
  unique_paths_approx INTEGER NOT NULL DEFAULT 0,
  sensitive_hits INTEGER NOT NULL DEFAULT 0,
  wp_login_hits INTEGER NOT NULL DEFAULT 0,
  bot_hits INTEGER NOT NULL DEFAULT 0,
  bytes_sum INTEGER NOT NULL DEFAULT 0,
  first_seen TEXT,
  last_seen TEXT,
  PRIMARY KEY (ip, bucket_minute)
);
CREATE INDEX IF NOT EXISTS idx_ip_time_buckets_minute ON ip_time_buckets(bucket_minute);

CREATE TABLE IF NOT EXISTS ip_time_bucket_paths (
  ip TEXT NOT NULL,
  bucket_minute TEXT NOT NULL,
  path_hash TEXT NOT NULL,
  path TEXT,
  PRIMARY KEY (ip, bucket_minute, path_hash),
  FOREIGN KEY (ip, bucket_minute) REFERENCES ip_time_buckets(ip, bucket_minute) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS schema_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ip_profiles (
  ip TEXT PRIMARY KEY, country TEXT, country_code TEXT, city TEXT, region TEXT,
  latitude REAL, longitude REAL, timezone TEXT, asn TEXT, organization TEXT, isp TEXT,
  network_type TEXT, ip_prefix TEXT,
  organization_confidence INTEGER NOT NULL DEFAULT 0,
  identity_evidence_json TEXT NOT NULL DEFAULT '[]',
  is_hosting INTEGER, is_vpn INTEGER, is_proxy INTEGER, is_tor INTEGER,
  proxy_type TEXT,
  abuse_score INTEGER, abuse_reports INTEGER, reputation_json TEXT NOT NULL DEFAULT '[]',
  enrichment_status TEXT NOT NULL DEFAULT 'partial',
  core_enrichment_status TEXT NOT NULL DEFAULT 'partial',
  privacy_enrichment_status TEXT NOT NULL DEFAULT 'unknown',
  threat_enrichment_status TEXT NOT NULL DEFAULT 'unknown',
  provider_errors_json TEXT NOT NULL DEFAULT '[]',
  provider_status_json TEXT NOT NULL DEFAULT '{}',
  field_sources_json TEXT NOT NULL DEFAULT '{}',
  next_retry_at TEXT, enrichment_attempts INTEGER NOT NULL DEFAULT 0,
  privacy_recheck_due_at TEXT,
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
  detections_json TEXT NOT NULL DEFAULT '[]',
  detections_recent_json TEXT NOT NULL DEFAULT '[]',
  ruleset_hash TEXT,
  evaluated_at TEXT,
  recent_first_seen TEXT,
  recent_last_seen TEXT,
  recent_requests INTEGER NOT NULL DEFAULT 0,
  recent_status_2xx INTEGER NOT NULL DEFAULT 0,
  recent_status_3xx INTEGER NOT NULL DEFAULT 0,
  recent_status_4xx INTEGER NOT NULL DEFAULT 0,
  recent_status_5xx INTEGER NOT NULL DEFAULT 0,
  recent_unique_paths INTEGER NOT NULL DEFAULT 0,
  recent_wp_login_requests INTEGER NOT NULL DEFAULT 0,
  recent_sensitive_probe_requests INTEGER NOT NULL DEFAULT 0,
  recent_bot_requests INTEGER NOT NULL DEFAULT 0,
  behavior_score_recent INTEGER NOT NULL DEFAULT 0,
  behavior_level_recent TEXT NOT NULL DEFAULT 'low',
  behavior_evidence_recent_json TEXT NOT NULL DEFAULT '[]',
  recent_updated_at TEXT,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ip_ai_scores (
  ip TEXT PRIMARY KEY,
  windows_seen INTEGER NOT NULL,
  anomalous_windows INTEGER NOT NULL,
  ai_anomaly_score INTEGER NOT NULL,
  ai_evidence_json TEXT NOT NULL DEFAULT '[]',
  model_mode TEXT NOT NULL,
  scored_at TEXT NOT NULL,
  confidence INTEGER NOT NULL DEFAULT 0,
  confidence_level TEXT NOT NULL DEFAULT 'low',
  previous_ai_anomaly_score INTEGER,
  score_delta INTEGER NOT NULL DEFAULT 0,
  score_reason TEXT NOT NULL DEFAULT 'legacy_snapshot',
  last_window_at TEXT,
  model_version TEXT
);
CREATE TABLE IF NOT EXISTS ai_model_state (
  model_key TEXT PRIMARY KEY,
  model_version TEXT,
  trained_at TEXT,
  training_start TEXT,
  training_end TEXT,
  training_windows INTEGER NOT NULL DEFAULT 0,
  training_ips INTEGER NOT NULL DEFAULT 0,
  training_decision_floor REAL,
  last_train_status TEXT,
  last_train_error TEXT,
  last_score_at TEXT,
  last_score_status TEXT,
  last_scored_event_id INTEGER NOT NULL DEFAULT 0,
  lease_owner TEXT,
  lease_expires_at TEXT,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS region_profiles (
  country_code TEXT PRIMARY KEY, country_name TEXT, economic_indicators_json TEXT,
  cultural_context_json TEXT, conflict_indicators_json TEXT, sources_json TEXT,
  observed_ip_count INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS log_sources (
  source_id TEXT PRIMARY KEY,
  log_key TEXT NOT NULL,
  last_offset INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'disabled',
  last_connected_at TEXT,
  last_event_at TEXT,
  last_error TEXT,
  lease_owner TEXT,
  lease_expires_at TEXT,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ip_change_log (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT NOT NULL,
  reason TEXT NOT NULL,
  changed_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ip_change_log_seq ON ip_change_log(seq);

CREATE TABLE IF NOT EXISTS ip_classification_state (
  ip TEXT PRIMARY KEY,
  label TEXT NOT NULL,
  score INTEGER NOT NULL,
  confidence INTEGER,
  updated_at TEXT NOT NULL,
  last_alert_at TEXT,
  last_alert_label TEXT
);

CREATE TABLE IF NOT EXISTS change_consumer_state (
  consumer_id TEXT PRIMARY KEY,
  last_seq INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active'
);

CREATE TABLE IF NOT EXISTS rule_firing_state (
  ip TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  ruleset_hash TEXT NOT NULL,
  first_fired_at TEXT NOT NULL,
  last_fired_at TEXT NOT NULL,
  last_seen_seq INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (ip, rule_id)
);

CREATE TABLE IF NOT EXISTS alert_outbox (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT NOT NULL,
  event_type TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  attempts INTEGER NOT NULL DEFAULT 0,
  next_retry_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  delivered_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_alert_outbox_due ON alert_outbox(status, next_retry_at);

CREATE TABLE IF NOT EXISTS ip_clusters (
  cluster_id TEXT PRIMARY KEY,
  asn TEXT,
  organization TEXT,
  member_ips_json TEXT NOT NULL DEFAULT '[]',
  shared_paths_json TEXT NOT NULL DEFAULT '[]',
  first_seen TEXT,
  last_seen TEXT,
  campaign_score INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ip_clusters_asn ON ip_clusters(asn);

CREATE TABLE IF NOT EXISTS ip_dispositions (
  ip TEXT PRIMARY KEY,
  state TEXT NOT NULL DEFAULT 'new',
  suggested_state TEXT,
  assigned_to TEXT,
  note TEXT,
  updated_at TEXT NOT NULL,
  history_json TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_ip_dispositions_state ON ip_dispositions(state);

CREATE TABLE IF NOT EXISTS privacy_networks (
  network TEXT NOT NULL, kind TEXT NOT NULL CHECK (kind IN ('vpn','proxy','datacenter')),
  provider TEXT, proxy_type TEXT, score REAL, source TEXT NOT NULL,
  first_seen TEXT, last_seen TEXT, checked_at TEXT, metadata_json TEXT NOT NULL DEFAULT '{}',
  active INTEGER NOT NULL DEFAULT 1, UNIQUE(source, kind, network)
);
CREATE INDEX IF NOT EXISTS idx_privacy_networks_network ON privacy_networks(network);
CREATE INDEX IF NOT EXISTS idx_privacy_networks_active ON privacy_networks(active, kind);

CREATE TABLE IF NOT EXISTS privacy_network_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT, network TEXT NOT NULL, kind TEXT NOT NULL,
  provider TEXT, proxy_type TEXT, score REAL, source TEXT NOT NULL,
  first_seen TEXT, last_seen TEXT, observed_at TEXT NOT NULL,
  metadata_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_privacy_history_source_observed ON privacy_network_history(source, observed_at);

CREATE TABLE IF NOT EXISTS threat_indicators (
  network TEXT NOT NULL, source TEXT NOT NULL, category TEXT NOT NULL,
  confidence REAL, first_seen TEXT, last_seen TEXT, checked_at TEXT,
  evidence_json TEXT NOT NULL DEFAULT '{}', active INTEGER NOT NULL DEFAULT 1,
  UNIQUE(network, source, category)
);
CREATE INDEX IF NOT EXISTS idx_threat_indicators_network ON threat_indicators(network);
CREATE INDEX IF NOT EXISTS idx_threat_indicators_active ON threat_indicators(active);

CREATE TABLE IF NOT EXISTS intel_source_status (
  source_name TEXT PRIMARY KEY, last_run_at TEXT, last_status TEXT,
  last_error TEXT, records_upserted INTEGER NOT NULL DEFAULT 0,
  metadata_json TEXT NOT NULL DEFAULT '{}'
);
"""

_seed_lock = threading.RLock()
_seed_cache: dict[tuple[str, str], tuple[int, int]] = {}

IP_PROFILE_COLUMNS = {
    "country_code": "TEXT",
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
    "proxy_type": "TEXT",
    "privacy_recheck_due_at": "TEXT",
}

def _migrate(conn: sqlite3.Connection) -> None:
    event_columns = {row["name"] for row in conn.execute("PRAGMA table_info(events)").fetchall()}
    if "source_offset" not in event_columns:
        conn.execute("ALTER TABLE events ADD COLUMN source_offset INTEGER")
    existing = {row["name"] for row in conn.execute("PRAGMA table_info(ip_profiles)").fetchall()}
    for column, definition in IP_PROFILE_COLUMNS.items():
        if column not in existing:
            conn.execute(f"ALTER TABLE ip_profiles ADD COLUMN {column} {definition}")
    ai_columns = {row["name"] for row in conn.execute("PRAGMA table_info(ip_ai_scores)").fetchall()}
    for column, definition in {
        "confidence": "INTEGER NOT NULL DEFAULT 0",
        "confidence_level": "TEXT NOT NULL DEFAULT 'low'",
        "previous_ai_anomaly_score": "INTEGER",
        "score_delta": "INTEGER NOT NULL DEFAULT 0",
        "score_reason": "TEXT NOT NULL DEFAULT 'legacy_snapshot'",
        "last_window_at": "TEXT",
        "model_version": "TEXT",
    }.items():
        if column not in ai_columns:
            conn.execute(f"ALTER TABLE ip_ai_scores ADD COLUMN {column} {definition}")
    conn.execute(
        """UPDATE ip_ai_scores SET score_reason='legacy_snapshot', last_window_at=scored_at
           WHERE last_window_at IS NULL"""
    )
    observation_columns = {row["name"] for row in conn.execute("PRAGMA table_info(ip_observations)").fetchall()}
    for column, definition in {
        "recent_first_seen": "TEXT",
        "recent_last_seen": "TEXT",
        "recent_requests": "INTEGER NOT NULL DEFAULT 0",
        "recent_status_2xx": "INTEGER NOT NULL DEFAULT 0",
        "recent_status_3xx": "INTEGER NOT NULL DEFAULT 0",
        "recent_status_4xx": "INTEGER NOT NULL DEFAULT 0",
        "recent_status_5xx": "INTEGER NOT NULL DEFAULT 0",
        "recent_unique_paths": "INTEGER NOT NULL DEFAULT 0",
        "recent_wp_login_requests": "INTEGER NOT NULL DEFAULT 0",
        "recent_sensitive_probe_requests": "INTEGER NOT NULL DEFAULT 0",
        "recent_bot_requests": "INTEGER NOT NULL DEFAULT 0",
        "behavior_score_recent": "INTEGER NOT NULL DEFAULT 0",
        "behavior_level_recent": "TEXT NOT NULL DEFAULT 'low'",
        "behavior_evidence_recent_json": "TEXT NOT NULL DEFAULT '[]'",
        "recent_updated_at": "TEXT",
        "detections_json": "TEXT NOT NULL DEFAULT '[]'",
        "detections_recent_json": "TEXT NOT NULL DEFAULT '[]'",
        "ruleset_hash": "TEXT",
        "evaluated_at": "TEXT",
    }.items():
        if column not in observation_columns:
            conn.execute(f"ALTER TABLE ip_observations ADD COLUMN {column} {definition}")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_ip_profiles_privacy_due "
        "ON ip_profiles(privacy_recheck_due_at)"
    )
    path_columns = {row["name"] for row in conn.execute("PRAGMA table_info(ip_time_bucket_paths)").fetchall()}
    if "path" not in path_columns:
        conn.execute("ALTER TABLE ip_time_bucket_paths ADD COLUMN path TEXT")
        import hashlib
        path_rows = conn.execute(
            "SELECT ip, bucket_minute, path_hash FROM ip_time_bucket_paths WHERE path IS NULL"
        ).fetchall()
        for row in path_rows:
            candidates = conn.execute(
                "SELECT path FROM events WHERE src_ip=? AND path IS NOT NULL AND substr(timestamp,1,16)=substr(?,1,16)",
                (row["ip"], row["bucket_minute"]),
            ).fetchall()
            path = next(
                (candidate["path"] for candidate in candidates
                 if hashlib.sha256((candidate["path"] or "").lower().encode("utf-8")).hexdigest() == row["path_hash"]),
                None,
            )
            if path is not None:
                conn.execute(
                    "UPDATE ip_time_bucket_paths SET path=? WHERE ip=? AND bucket_minute=? AND path_hash=?",
                    (path, row["ip"], row["bucket_minute"], row["path_hash"]),
                )
    bucket_columns = {row["name"] for row in conn.execute("PRAGMA table_info(ip_time_buckets)").fetchall()}
    for column in ("status_403", "status_404", "post_requests"):
        if column not in bucket_columns:
            conn.execute(f"ALTER TABLE ip_time_buckets ADD COLUMN {column} INTEGER NOT NULL DEFAULT 0")

    marker = conn.execute(
        "SELECT value FROM schema_meta WHERE key = 'time_buckets_backfilled'"
    ).fetchone()
    if not marker:
        conn.execute(
            """
            INSERT OR IGNORE INTO ip_time_buckets
              (ip, bucket_minute, requests, status_2xx, status_3xx, status_4xx, status_5xx, status_403, status_404, post_requests,
               sensitive_hits, wp_login_hits, bot_hits, bytes_sum, first_seen, last_seen)
            SELECT src_ip, substr(timestamp, 1, 16) || ':00+00:00', COUNT(*),
              SUM(CASE WHEN status BETWEEN 200 AND 299 THEN 1 ELSE 0 END),
              SUM(CASE WHEN status BETWEEN 300 AND 399 THEN 1 ELSE 0 END),
              SUM(CASE WHEN status BETWEEN 400 AND 499 THEN 1 ELSE 0 END),
              SUM(CASE WHEN status >= 500 THEN 1 ELSE 0 END),
              SUM(CASE WHEN status = 403 THEN 1 ELSE 0 END),
              SUM(CASE WHEN status = 404 THEN 1 ELSE 0 END),
              SUM(CASE WHEN upper(method) = 'POST' THEN 1 ELSE 0 END),
              SUM(CASE WHEN lower(path) LIKE '/.env%' OR lower(path) LIKE '/.git%'
                    OR lower(path) LIKE '%wp-config.php%' OR lower(path) LIKE '%xmlrpc.php%'
                    OR lower(path) LIKE '%phpmyadmin%' OR lower(path) LIKE '%adminer%'
                    OR lower(path) LIKE '%vendor/phpunit%' THEN 1 ELSE 0 END),
              SUM(CASE WHEN lower(path) LIKE '%/wp-login.php%' THEN 1 ELSE 0 END),
              SUM(CASE WHEN lower(COALESCE(user_agent, '')) LIKE '%bot%'
                    OR lower(COALESCE(user_agent, '')) LIKE '%spider%'
                    OR lower(COALESCE(user_agent, '')) LIKE '%crawler%'
                    OR lower(COALESCE(user_agent, '')) LIKE '%feedfetcher%'
                    OR lower(COALESCE(user_agent, '')) LIKE '%archive.org_bot%' THEN 1 ELSE 0 END),
              COALESCE(SUM(bytes_sent), 0), MIN(timestamp), MAX(timestamp)
            FROM events
            WHERE timestamp IS NOT NULL
            GROUP BY src_ip, substr(timestamp, 1, 16)
            """
        )
        import hashlib
        for event in conn.execute("SELECT src_ip, timestamp, path FROM events WHERE timestamp IS NOT NULL AND path IS NOT NULL"):
            conn.execute(
                "INSERT OR IGNORE INTO ip_time_bucket_paths(ip, bucket_minute, path_hash, path) VALUES (?, ?, ?, ?)",
                (event["src_ip"], str(event["timestamp"])[:16] + ":00+00:00",
                 hashlib.sha256(event["path"].lower().encode("utf-8")).hexdigest(), event["path"]),
            )
        conn.execute(
            """
            UPDATE ip_time_buckets SET unique_paths_approx = (
              SELECT COUNT(*) FROM ip_time_bucket_paths p
              WHERE p.ip = ip_time_buckets.ip AND p.bucket_minute = ip_time_buckets.bucket_minute
            )
            """
        )
        conn.execute(
            "INSERT INTO schema_meta(key, value) VALUES ('time_buckets_backfilled', '1')"
        )


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
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_events_stream_offset "
        "ON events(source, source_offset) WHERE source_offset IS NOT NULL"
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ip_profiles_country_code ON ip_profiles(country_code)")
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
