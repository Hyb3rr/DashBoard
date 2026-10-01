"""PostgreSQL state repositories.

Repositories deliberately expose dictionaries, matching the current API
contract while keeping SQL/backend knowledge out of route handlers.
"""

from __future__ import annotations

from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from .alert_repository import (
    AlertRepository,
    CRITICAL_ALERT_REPEAT_COOLDOWN,
    _alert_evidence_for_classification,
    create_classification_alert,
    persist_classification_alert_and_notification,
    should_create_alert,
    should_create_critical_recurrence,
)
from .json_codec import decode_json as _decode_json
from .json_codec import json_bytes as _json_bytes
from .json_codec import jsonb_value as _json
from .postgres import transaction
from .state_repository import StateRepository
from ..core import metrics
from ..services.dispositions import automatic_transition, recommendation
from .checkpoints import CheckpointCommitRejected, CheckpointRepository
from .region_repository import RegionRepository
from .detection_repository import (
    PgDetectionRepository,
    _build_recent_behavior_fields,
    _feature_deltas,
    _rolling_peak_5m,
    _rolling_peaks_by_ip,
    _select_recent_behavior_window,
    _upsert_feature_deltas,
    _utc_minute,
)


class ProfileRepository:
    def get(self, ip: str) -> dict[str, Any] | None:
        """Fetch the persisted intelligence profile for one IP address."""
        with transaction() as conn:
            row = conn.execute("SELECT * FROM ip_profiles WHERE ip=%s", (ip,)).fetchone()
        return dict(row) if row else None

    def upsert(self, profile: dict[str, Any], conn=None) -> None:
        """Insert or refresh the current intelligence profile for an IP."""
        scope = transaction() if conn is None else nullcontext(conn)
        with scope as conn:
            conn.execute(
                """INSERT INTO ip_profiles
                   (ip,country,country_code,city,region,latitude,longitude,timezone,asn,
                    organization,isp,network_type,ip_prefix,organization_confidence,
                    identity_evidence,is_hosting,is_vpn,is_proxy,is_tor,proxy_type,
                    abuse_score,abuse_reports,reputation,enrichment_status,
                    core_enrichment_status,privacy_enrichment_status,threat_enrichment_status,
                    provider_errors,provider_status,field_sources,next_retry_at,
                    enrichment_attempts,privacy_recheck_due_at,risk_score,risk_level,evidence,
                    sources,fetched_at,updated_at)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                           %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                   ON CONFLICT (ip) DO UPDATE SET country=EXCLUDED.country,
                    country_code=EXCLUDED.country_code, city=EXCLUDED.city, region=EXCLUDED.region,
                    latitude=EXCLUDED.latitude, longitude=EXCLUDED.longitude, timezone=EXCLUDED.timezone,
                    asn=EXCLUDED.asn, organization=EXCLUDED.organization, isp=EXCLUDED.isp,
                    network_type=EXCLUDED.network_type, ip_prefix=EXCLUDED.ip_prefix,
                    organization_confidence=EXCLUDED.organization_confidence,
                    identity_evidence=EXCLUDED.identity_evidence, is_hosting=EXCLUDED.is_hosting,
                    is_vpn=EXCLUDED.is_vpn, is_proxy=EXCLUDED.is_proxy, is_tor=EXCLUDED.is_tor,
                    proxy_type=EXCLUDED.proxy_type, abuse_score=EXCLUDED.abuse_score,
                    abuse_reports=EXCLUDED.abuse_reports, reputation=EXCLUDED.reputation,
                    enrichment_status=EXCLUDED.enrichment_status,
                    core_enrichment_status=EXCLUDED.core_enrichment_status,
                    privacy_enrichment_status=EXCLUDED.privacy_enrichment_status,
                    threat_enrichment_status=EXCLUDED.threat_enrichment_status,
                    provider_errors=EXCLUDED.provider_errors, provider_status=EXCLUDED.provider_status,
                    field_sources=EXCLUDED.field_sources, next_retry_at=EXCLUDED.next_retry_at,
                    enrichment_attempts=EXCLUDED.enrichment_attempts,
                    privacy_recheck_due_at=EXCLUDED.privacy_recheck_due_at,
                    sources=EXCLUDED.sources, fetched_at=EXCLUDED.fetched_at,
                    updated_at=EXCLUDED.updated_at""",
                (
                    profile.get("ip"), profile.get("country"), profile.get("country_code"),
                    profile.get("city"), profile.get("region"), profile.get("latitude"),
                    profile.get("longitude"), profile.get("timezone"), profile.get("asn"),
                    profile.get("organization"), profile.get("isp"), profile.get("network_type"),
                    profile.get("ip_prefix"), profile.get("organization_confidence", 0),
                    _json(profile.get("identity_evidence", [])), profile.get("is_hosting"),
                    profile.get("is_vpn"), profile.get("is_proxy"), profile.get("is_tor"),
                    profile.get("proxy_type"), profile.get("abuse_score"), profile.get("abuse_reports"),
                    _json(profile.get("reputation", [])), profile.get("enrichment_status", "partial"),
                    profile.get("core_enrichment_status", "partial"), profile.get("privacy_enrichment_status", "unknown"),
                    profile.get("threat_enrichment_status", "unknown"), _json(profile.get("provider_errors", [])),
                    _json(profile.get("provider_status", {})), _json(profile.get("field_sources", {})),
                    profile.get("next_retry_at"), profile.get("enrichment_attempts", 0),
                    profile.get("privacy_recheck_due_at"), profile.get("risk_score", 0),
                    profile.get("risk_level", "unknown"), _json(profile.get("evidence", [])),
                    _json(profile.get("sources", [])), profile.get("fetched_at") or datetime.now(timezone.utc),
                    datetime.now(timezone.utc),
                ),
            )
            self._upsert_network_location(conn, profile)

    @staticmethod
    def _upsert_network_location(conn, profile: dict[str, Any]) -> None:
        """Persist the canonical network-location fields for an IP profile."""
        conn.execute(
            """UPDATE ip_profiles SET network_location=%s,location_confidence=%s,location_disputed=%s,
               location_scope=%s,network_type_source=%s,asn_source=%s,geo_sources=%s,
               geo_resolved_at=%s,geo_expires_at=%s WHERE ip=%s""",
            (
                _json(profile.get("network_location", {})), int(profile.get("location_confidence", 0) or 0),
                bool(profile.get("location_disputed", False)), profile.get("location_scope"),
                profile.get("network_type_source"), profile.get("asn_source"), _json(profile.get("geo_sources", [])),
                profile.get("geo_resolved_at"), profile.get("geo_expires_at"), profile.get("ip"),
            ),
        )

    def country_demand_metadata(self, ips: Iterable[str]) -> dict[str, dict[str, Any]]:
        """Load country-demand qualification fields for a batch of IPs."""
        values = [str(value) for value in ips if value]
        if not values:
            return {}
        with transaction() as conn:
            rows = conn.execute(
                """SELECT host(p.ip) AS ip,p.country_code,p.is_tor,p.is_hosting,p.is_vpn,p.is_proxy,
                          p.network_type,p.abuse_score,cs.label,p.city,p.latitude,p.longitude,
                          p.location_disputed,p.location_scope,p.network_location
                     FROM ip_profiles p
                     LEFT JOIN ip_classification_state cs ON cs.ip=p.ip
                    WHERE p.ip = ANY(%s::inet[])""",
                (values,),
            ).fetchall()
        return {str(row["ip"]): dict(row) for row in rows}
class GeoRepository:
    def persist_resolution(self, ip: str, data: dict[str, Any], ttl_days: int = 14, conn=None) -> None:
        """Persist one resolved network location with its validity period."""
        expires = datetime.now(timezone.utc) + timedelta(days=ttl_days)
        scope = transaction() if conn is None else nullcontext(conn)
        with scope as conn:
            conn.execute("""INSERT INTO geo_resolutions(ip,network,asn,organization,network_type,country,country_code,latitude,longitude,city,city_source,city_disputed,city_confidence,city_distance_km,confidence,disputed,location_scope,source_ids,evidence,ruleset_version,resolved_at,expires_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'geo-v5',now(),%s)
                ON CONFLICT(ip) DO UPDATE SET network=EXCLUDED.network,asn=EXCLUDED.asn,organization=EXCLUDED.organization,network_type=EXCLUDED.network_type,country=EXCLUDED.country,country_code=EXCLUDED.country_code,latitude=EXCLUDED.latitude,longitude=EXCLUDED.longitude,city=EXCLUDED.city,city_source=EXCLUDED.city_source,city_disputed=EXCLUDED.city_disputed,city_confidence=EXCLUDED.city_confidence,city_distance_km=EXCLUDED.city_distance_km,confidence=EXCLUDED.confidence,disputed=EXCLUDED.disputed,location_scope=EXCLUDED.location_scope,source_ids=EXCLUDED.source_ids,evidence=EXCLUDED.evidence,ruleset_version=EXCLUDED.ruleset_version,resolved_at=EXCLUDED.resolved_at,expires_at=EXCLUDED.expires_at""", (ip, data.get("network"), data.get("asn"), data.get("organization"), data.get("network_type"), data.get("country"), data.get("country_code"), data.get("latitude"), data.get("longitude"), data.get("city"), data.get("city_source"), bool(data.get("city_disputed")), data.get("city_confidence"), data.get("city_distance_km"), int(data.get("confidence", 0) or 0), bool(data.get("disputed")), data.get("scope"), _json(data.get("sources", [])), _json({"confidence_breakdown": data.get("confidence_breakdown", {}), "registration": data.get("registration")}), expires))


class ObservationRepository:
    def get(self, ip: str) -> dict[str, Any] | None:
        """Fetch and decode the current observation payload for an IP."""
        with transaction() as conn:
            row = conn.execute("SELECT payload,ruleset_hash,updated_at FROM ip_observations_state WHERE ip=%s", (ip,)).fetchone()
        if not row:
            return None
        result = _decode_json(row["payload"])
        result = result if isinstance(result, dict) else {}
        result["ruleset_hash"] = row["ruleset_hash"]
        result["updated_at"] = row["updated_at"]
        return result

    def upsert(self, ip: str, observation: dict[str, Any], ruleset: str | None = None) -> None:
        """Insert or refresh one observation and its ruleset version."""
        with transaction() as conn:
            conn.execute(
                """INSERT INTO ip_observations_state(ip,payload,ruleset_hash,updated_at)
                   VALUES (%s,%s,%s,%s)
                   ON CONFLICT(ip) DO UPDATE SET payload=EXCLUDED.payload,
                    ruleset_hash=EXCLUDED.ruleset_hash, updated_at=EXCLUDED.updated_at""",
                (ip, _json(observation), ruleset, datetime.now(timezone.utc)),
            )

    def upsert_rare_path_evidence(self, values: dict[str, list[dict[str, Any]]], dataset_id: str = "live") -> list[str]:
        """Attach changed rare-path evidence to profiles that already exist."""
        if not values:
            return []
        changed = []
        with transaction() as conn:
            for ip, evidence in values.items():
                result = conn.execute(
                    """UPDATE ip_observations_state
                       SET payload=jsonb_set(payload,'{rare_path_evidence}',%s::jsonb,true), updated_at=now()
                     WHERE ip=%s AND payload->'rare_path_evidence' IS DISTINCT FROM %s::jsonb""",
                    (_json(evidence), ip, _json(evidence)),
                )
                if result.rowcount:
                    conn.execute(
                        "INSERT INTO ip_change_log(dataset_id,ip,reason,changed_at) VALUES(%s,%s,'rare_path_evidence_updated',now())",
                        (dataset_id, ip),
                    )
                    changed.append(ip)
        return changed


class ClassificationRepository:
    def get(self, ip: str) -> dict[str, Any] | None:
        """Fetch the current classification state for one IP."""
        with transaction() as conn:
            row = conn.execute("SELECT * FROM ip_classification_state WHERE ip=%s", (ip,)).fetchone()
        return dict(row) if row else None

    def upsert(self, ip: str, label: str, score: int, confidence: int | None = None) -> None:
        """Insert or update one IP's authoritative classification result."""
        with transaction() as conn:
            conn.execute(
                """INSERT INTO ip_classification_state(ip,label,score,confidence,updated_at)
                   VALUES (%s,%s,%s,%s,%s)
                   ON CONFLICT(ip) DO UPDATE SET label=EXCLUDED.label,score=EXCLUDED.score,
                    confidence=EXCLUDED.confidence,updated_at=EXCLUDED.updated_at""",
                (ip, label, score, confidence, datetime.now(timezone.utc)),
            )


class IntelligenceRepository:
    def networks_for_ip(self, ip: str) -> dict[str, list[dict[str, Any]]]:
        """Return active privacy and threat network matches for one IP."""
        with transaction() as conn:
            privacy = conn.execute(
                "SELECT * FROM privacy_networks WHERE active AND network >>= %s::inet", (ip,)
            ).fetchall()
            threats = conn.execute(
                "SELECT * FROM threat_indicators WHERE active AND network >>= %s::inet", (ip,)
            ).fetchall()
        return {"privacy": [dict(row) for row in privacy], "threat": [dict(row) for row in threats]}


class FeatureRepository:
    """Bulk PostgreSQL minute features used by the detection plane."""

    def upsert_events(self, events: Iterable[dict[str, Any]], dataset_id: str = "live") -> int:
        """Aggregate and upsert minute-level request features for events."""
        buckets, paths = _feature_deltas(events)
        if not buckets:
            return 0
        with transaction() as conn:
            _upsert_feature_deltas(conn, buckets, paths, dataset_id)
        return sum(int(row["requests"]) for row in buckets.values())


class AiRepository:
    """PostgreSQL state boundary for model metadata and anomaly scores."""

    def state(self, model_key: str) -> dict[str, Any] | None:
        """Fetch the persisted lifecycle state for one AI model bundle."""
        with transaction() as conn:
            row = conn.execute("SELECT * FROM ai_model_state WHERE model_key=%s", (model_key,)).fetchone()
        return dict(row) if row else None

    def scores(self, ips: Iterable[str]) -> list[dict[str, Any]]:
        """Fetch stored anomaly scores for the requested IP batch."""
        values = list(ips)
        if not values:
            return []
        with transaction() as conn:
            rows = conn.execute("SELECT * FROM ip_ai_scores WHERE ip=ANY(%s::inet[])", (values,)).fetchall()
        return [dict(row) for row in rows]

    def summary(self) -> dict[str, Any]:
        """Summarize anomaly-score coverage and flagged identities."""
        with transaction() as conn:
            row = conn.execute("""WITH identities AS (
                    SELECT ip FROM ip_observations_state UNION SELECT ip FROM ip_profiles
                )
                SELECT COUNT(*) AS total,
                       COUNT(ai.ip) AS scored,
                       COUNT(ai.ip) FILTER (WHERE ai.ai_anomaly_score >= 70) AS flagged
                  FROM identities i LEFT JOIN ip_ai_scores ai ON ai.ip=i.ip""").fetchone()
        total = int(row["total"] or 0)
        scored = int(row["scored"] or 0)
        return {
            "scored": scored,
            "flagged": int(row["flagged"] or 0),
            "coverage": round(scored * 100 / total, 2) if total else 0,
        }



class DispositionRepository:
    def set(self, ip: str, state: str, assigned_to: str | None, note: str | None, actor: str, label: str | None) -> dict[str, Any]:
        """Persist an analyst disposition and append its audit history."""
        suggestion = {"critical": "investigate", "medium": "monitor"}.get(label)
        now = datetime.now(timezone.utc)
        with transaction() as conn:
            row = conn.execute("SELECT * FROM ip_dispositions WHERE ip=%s", (ip,)).fetchone()
            current = dict(row) if row else {"state": "new", "history": []}
            history = current.get("history") or []
            history.append({"at": now.isoformat(), "actor": actor or "system", "from": current.get("state", "new"), "to": state, "assigned_to": assigned_to, "note": note})
            conn.execute("""INSERT INTO ip_dispositions(ip,state,suggested_state,assigned_to,note,updated_at,history)
                VALUES (%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(ip) DO UPDATE SET state=EXCLUDED.state,suggested_state=EXCLUDED.suggested_state,assigned_to=EXCLUDED.assigned_to,note=EXCLUDED.note,updated_at=EXCLUDED.updated_at""", (ip, state, suggestion, assigned_to, note, now, _json(history)))
            result = conn.execute("SELECT * FROM ip_dispositions WHERE ip=%s", (ip,)).fetchone()
        return dict(result)

    @staticmethod
    def apply_automatic_transition(
        conn,
        *,
        ip: str,
        classification_label: str | None,
        alert_result: dict[str, Any] | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any] | None:
        """Apply one policy-approved transition on the caller's transaction."""
        at = now or datetime.now(timezone.utc)
        alert_reason_type = (
            alert_result.get("reason_type")
            if alert_result and alert_result.get("created")
            else None
        )
        for _ in range(2):
            row = conn.execute(
                "SELECT state,assigned_to,note,history FROM ip_dispositions WHERE ip=%s FOR UPDATE",
                (ip,),
            ).fetchone()
            current = dict(row) if row else {"state": "new", "history": []}
            from_state = str(current.get("state") or "new").lower()
            transition = automatic_transition(from_state, classification_label, alert_reason_type)
            if transition is None:
                return None
            to_state, reason = transition
            history = _decode_json(current.get("history")) or []
            if not isinstance(history, list):
                history = []
            history.append({
                "at": at.isoformat(),
                "actor": "system",
                "from": from_state,
                "to": to_state,
                "reason": reason,
            })
            suggested_state = recommendation(classification_label)
            if row:
                conn.execute(
                    """UPDATE ip_dispositions
                       SET state=%s,suggested_state=%s,updated_at=%s,history=%s
                       WHERE ip=%s AND state=%s""",
                    (to_state, suggested_state, at, _json(history), ip, from_state),
                )
                return {"from": from_state, "to": to_state, "reason": reason}

            # Serialize first-time transitions so a concurrent Critical write
            # cannot be overwritten by a stale NEW -> MONITOR decision.
            conn.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s::text,0))",
                (ip,),
            )
            row = conn.execute(
                "SELECT state,assigned_to,note,history FROM ip_dispositions WHERE ip=%s FOR UPDATE",
                (ip,),
            ).fetchone()
            if row:
                continue
            inserted = conn.execute(
                """INSERT INTO ip_dispositions(ip,state,suggested_state,updated_at,history)
                   VALUES (%s,%s,%s,%s,%s) ON CONFLICT(ip) DO NOTHING RETURNING ip""",
                (ip, to_state, suggested_state, at, _json(history)),
            )
            if inserted is not None and inserted.fetchone():
                return {"from": from_state, "to": to_state, "reason": reason}
        return None
