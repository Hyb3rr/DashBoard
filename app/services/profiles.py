"""Profile persistence and classification composition.

Keeping these operations outside the route module makes the API layer mostly
about HTTP concerns and gives background jobs one place to reuse profile IO.
"""

from datetime import datetime, timezone

from ..core.db import decode, encode, region_profile
from ..core.enrichment import lookup
from ..core.intelligence import classify_ip


def profile_from_row(row):
    data = dict(row)
    for column, key in (
        ("evidence_json", "evidence"),
        ("source_json", "sources"),
        ("identity_evidence_json", "identity_evidence"),
        ("reputation_json", "reputation"),
        ("provider_errors_json", "provider_errors"),
        ("provider_status_json", "provider_status"),
        ("field_sources_json", "field_sources"),
    ):
        data[key] = decode(data.pop(column))
    return data


def classification_observation(row: dict) -> dict:
    return {
        "behavior_score": row.get("behavior_score", 0),
        "requests": row.get("requests", 0),
        "status_4xx": row.get("status_4xx", 0),
        "status_5xx": row.get("status_5xx", 0),
        "unique_paths": row.get("unique_paths", 0),
        "wp_login_requests": row.get("wp_login_requests", 0),
        "sensitive_probe_requests": row.get("sensitive_probe_requests", 0),
        "bot_requests": row.get("bot_requests", 0),
    }


def ai_profile_for_ip(conn, ip: str | None) -> dict | None:
    if not ip:
        return None
    row = conn.execute("SELECT * FROM ip_ai_scores WHERE ip = ?", (ip,)).fetchone()
    if not row:
        return None
    data = dict(row)
    data["ai_evidence"] = decode(data.pop("ai_evidence_json"))
    return data


def attach_region_and_classification(conn, data: dict, observation: dict | None = None) -> dict:
    region = region_profile(conn, data.get("country_code"))
    if region:
        data["region_profile"] = region
    ai_profile = ai_profile_for_ip(conn, data.get("ip"))
    if ai_profile:
        data["ai_profile"] = ai_profile
    classification = classify_ip(data, observation, region, ai_profile)
    data["classification"] = classification
    data["threat_signal_score"] = classification["score"]
    data["threat_signal_label"] = classification["label"]
    return data


def _db_bool(value):
    return None if value is None else int(bool(value))


def retry_due(row) -> bool:
    if row["core_enrichment_status"] == "complete" and not row["next_retry_at"]:
        return False
    if not row["next_retry_at"]:
        return True
    try:
        return datetime.fromisoformat(row["next_retry_at"]) <= datetime.now(timezone.utc)
    except ValueError:
        return True


def store_profile(conn, data: dict) -> None:
    conn.execute("""INSERT OR REPLACE INTO ip_profiles
      (ip,country,country_code,city,region,latitude,longitude,timezone,asn,organization,isp,
       network_type,ip_prefix,organization_confidence,identity_evidence_json,
       is_hosting,is_vpn,is_proxy,is_tor,abuse_score,abuse_reports,reputation_json,
       enrichment_status,core_enrichment_status,privacy_enrichment_status,threat_enrichment_status,
       provider_errors_json,next_retry_at,enrichment_attempts,
       provider_status_json,field_sources_json,
       risk_score,risk_level,evidence_json,source_json,fetched_at)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
      data["ip"], data.get("country"), data.get("country_code"), data.get("city"), data.get("region"),
      data.get("latitude"), data.get("longitude"), data.get("timezone"), data.get("asn"), data.get("organization"), data.get("isp"),
      data.get("network_type"), data.get("ip_prefix"), int(data.get("organization_confidence", 0)), encode(data.get("identity_evidence")),
      _db_bool(data.get("is_hosting")), _db_bool(data.get("is_vpn")), _db_bool(data.get("is_proxy")), _db_bool(data.get("is_tor")),
      data.get("abuse_score"), data.get("abuse_reports"), encode(data.get("reputation")),
      data.get("enrichment_status", "failed"), data.get("core_enrichment_status", "failed"),
      data.get("privacy_enrichment_status", "unknown"), data.get("threat_enrichment_status", "unknown"),
      encode(data.get("provider_errors")), data.get("next_retry_at"), data.get("enrichment_attempts", 1),
      encode(data.get("provider_status")), encode(data.get("field_sources")),
      data["risk_score"], data["risk_level"], encode(data["evidence"]), encode(data["sources"]), data["fetched_at"]))


async def ensure_profile(conn, ip: str, refresh: bool = False):
    row = conn.execute("SELECT * FROM ip_profiles WHERE ip = ?", (ip,)).fetchone()
    if row and not refresh and not retry_due(row):
        return profile_from_row(row), None
    try:
        attempt = (row["enrichment_attempts"] if row else 0) + 1
        data = await lookup(ip, attempt=attempt)
    except Exception as exc:
        return None, f"{ip}: {type(exc).__name__}"
    store_profile(conn, data)
    return data, None
