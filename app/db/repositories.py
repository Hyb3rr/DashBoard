"""PostgreSQL state repositories.

Repositories deliberately expose dictionaries, matching the current API
contract while keeping SQL/backend knowledge out of route handlers.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from psycopg.types.json import Jsonb

from .postgres import connect, transaction
from ..core.rules import BehaviorContext, run_rules, ruleset_hash
from ..core.intelligence import classify_ip
from ..testing.clock import utcnow
from ..testing.failpoints import NoopFailpoint
from ..core.regions import market_score, normalise_conflict_indicators, normalise_economic_indicators
from ..core import metrics


def _json(value: Any) -> Any:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            pass
    return Jsonb(value)


def _decode_json(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


class ProfileRepository:
    def get(self, ip: str) -> dict[str, Any] | None:
        with transaction() as conn:
            row = conn.execute("SELECT * FROM ip_profiles WHERE ip=%s", (ip,)).fetchone()
        return dict(row) if row else None

    def upsert(self, profile: dict[str, Any]) -> None:
        with transaction() as conn:
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
                    provider_status=EXCLUDED.provider_status, field_sources=EXCLUDED.field_sources,
                    enrichment_status=EXCLUDED.enrichment_status, fetched_at=EXCLUDED.fetched_at,
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


class GeoRepository:
    def persist_resolution(self, ip: str, data: dict[str, Any], ttl_days: int = 14) -> None:
        expires = datetime.now(timezone.utc) + timedelta(days=ttl_days)
        with transaction() as conn:
            conn.execute("""INSERT INTO geo_resolutions(ip,network,asn,organization,network_type,country,country_code,latitude,longitude,city,city_source,city_disputed,city_confidence,city_distance_km,confidence,disputed,location_scope,source_ids,evidence,ruleset_version,resolved_at,expires_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'geo-v3',now(),%s)
                ON CONFLICT(ip) DO UPDATE SET network=EXCLUDED.network,asn=EXCLUDED.asn,organization=EXCLUDED.organization,network_type=EXCLUDED.network_type,country=EXCLUDED.country,country_code=EXCLUDED.country_code,latitude=EXCLUDED.latitude,longitude=EXCLUDED.longitude,city=EXCLUDED.city,city_source=EXCLUDED.city_source,city_disputed=EXCLUDED.city_disputed,city_confidence=EXCLUDED.city_confidence,city_distance_km=EXCLUDED.city_distance_km,confidence=EXCLUDED.confidence,disputed=EXCLUDED.disputed,location_scope=EXCLUDED.location_scope,source_ids=EXCLUDED.source_ids,evidence=EXCLUDED.evidence,ruleset_version=EXCLUDED.ruleset_version,resolved_at=EXCLUDED.resolved_at,expires_at=EXCLUDED.expires_at""", (ip, data.get("network"), data.get("asn"), data.get("organization"), data.get("network_type"), data.get("country"), data.get("country_code"), data.get("latitude"), data.get("longitude"), data.get("city"), data.get("city_source"), bool(data.get("city_disputed")), data.get("city_confidence"), data.get("city_distance_km"), int(data.get("confidence", 0) or 0), bool(data.get("disputed")), data.get("scope"), _json(data.get("sources", [])), _json({"confidence_breakdown": data.get("confidence_breakdown", {}), "registration": data.get("registration")}), expires))


class ObservationRepository:
    def get(self, ip: str) -> dict[str, Any] | None:
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
        with transaction() as conn:
            conn.execute(
                """INSERT INTO ip_observations_state(ip,payload,ruleset_hash,updated_at)
                   VALUES (%s,%s,%s,%s)
                   ON CONFLICT(ip) DO UPDATE SET payload=EXCLUDED.payload,
                    ruleset_hash=EXCLUDED.ruleset_hash, updated_at=EXCLUDED.updated_at""",
                (ip, _json(observation), ruleset, datetime.now(timezone.utc)),
            )

    def upsert_rare_path_evidence(self, values: dict[str, list[dict[str, Any]]]) -> None:
        if not values:
            return
        with transaction() as conn:
            for ip, evidence in values.items():
                conn.execute(
                    """UPDATE ip_observations_state
                       SET payload=jsonb_set(payload,'{rare_path_evidence}',%s::jsonb,true), updated_at=now()
                     WHERE ip=%s""",
                    (_json(evidence), ip),
                )


class ClassificationRepository:
    def get(self, ip: str) -> dict[str, Any] | None:
        with transaction() as conn:
            row = conn.execute("SELECT * FROM ip_classification_state WHERE ip=%s", (ip,)).fetchone()
        return dict(row) if row else None

    def upsert(self, ip: str, label: str, score: int, confidence: int | None = None) -> None:
        with transaction() as conn:
            conn.execute(
                """INSERT INTO ip_classification_state(ip,label,score,confidence,updated_at)
                   VALUES (%s,%s,%s,%s,%s)
                   ON CONFLICT(ip) DO UPDATE SET label=EXCLUDED.label,score=EXCLUDED.score,
                    confidence=EXCLUDED.confidence,updated_at=EXCLUDED.updated_at""",
                (ip, label, score, confidence, datetime.now(timezone.utc)),
            )


class AlertRepository:
    def pending(self, limit: int = 50) -> list[dict[str, Any]]:
        with transaction() as conn:
            rows = conn.execute(
                "SELECT * FROM alert_outbox WHERE status='pending' AND next_retry_at<=now() ORDER BY id LIMIT %s",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]


class IntelligenceRepository:
    def networks_for_ip(self, ip: str) -> dict[str, list[dict[str, Any]]]:
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
        buckets, paths = _feature_deltas(events)
        if not buckets:
            return 0
        with transaction() as conn:
            _upsert_feature_deltas(conn, buckets, paths, dataset_id)
        return sum(int(row["requests"]) for row in buckets.values())


class AiRepository:
    """PostgreSQL state boundary for model metadata and anomaly scores."""

    def state(self, model_key: str) -> dict[str, Any] | None:
        with transaction() as conn:
            row = conn.execute("SELECT * FROM ai_model_state WHERE model_key=%s", (model_key,)).fetchone()
        return dict(row) if row else None

    def scores(self, ips: Iterable[str]) -> list[dict[str, Any]]:
        values = list(ips)
        if not values:
            return []
        with transaction() as conn:
            rows = conn.execute("SELECT * FROM ip_ai_scores WHERE ip=ANY(%s::inet[])", (values,)).fetchall()
        return [dict(row) for row in rows]


def _feature_deltas(events: Iterable[dict[str, Any]]) -> tuple[dict, dict]:
    buckets: dict[tuple[str, str], dict[str, Any]] = {}
    paths: dict[tuple[str, str, str], dict[str, Any]] = {}
    for event in events:
            timestamp = event.get("timestamp")
            ip = event.get("src_ip")
            if not timestamp or not ip:
                continue
            stamp = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00")).astimezone(timezone.utc)
            minute = stamp.replace(second=0, microsecond=0).isoformat()
            key = (str(ip), minute)
            row = buckets.setdefault(key, {
                "requests": 0, "status_2xx": 0, "status_3xx": 0, "status_4xx": 0,
                "status_5xx": 0, "status_403": 0, "status_404": 0, "post_requests": 0,
                "sensitive_hits": 0, "wp_login_hits": 0, "bot_hits": 0, "bytes_sum": 0,
                "first_seen": stamp, "last_seen": stamp,
            })
            status = int(event.get("status") or 0)
            path = str(event.get("path") or "")
            ua = str(event.get("user_agent") or "").lower()
            row["requests"] += 1
            row["status_2xx"] += int(200 <= status < 300)
            row["status_3xx"] += int(300 <= status < 400)
            row["status_4xx"] += int(400 <= status < 500)
            row["status_5xx"] += int(status >= 500)
            row["status_403"] += int(status == 403)
            row["status_404"] += int(status == 404)
            row["post_requests"] += int(str(event.get("method") or "").upper() == "POST")
            row["sensitive_hits"] += int(any(x in path.lower() for x in ("/.env", "/.git", "wp-config.php", "/xmlrpc.php", "/phpmyadmin", "/adminer")))
            row["wp_login_hits"] += int("/wp-login.php" in path.lower())
            row["bot_hits"] += int(any(x in ua for x in ("bot", "spider", "crawler", "feedfetcher")))
            row["bytes_sum"] += int(event.get("bytes_sent") or 0)
            row["first_seen"] = min(row["first_seen"], stamp)
            row["last_seen"] = max(row["last_seen"], stamp)
            if path:
                pkey = (str(ip), minute, path)
                prow = paths.setdefault(pkey, {"requests": 0, "status_4xx": 0, "status_5xx": 0})
                prow["requests"] += 1
                prow["status_4xx"] += int(400 <= status < 500)
                prow["status_5xx"] += int(status >= 500)
    return buckets, paths


def _upsert_feature_deltas(conn, buckets: dict, paths: dict, dataset_id: str) -> None:
    if not buckets:
        return
    with conn.cursor() as cur:
                cur.executemany(
                """INSERT INTO ip_minute_features
                (dataset_id,ip,bucket_minute,requests,status_2xx,status_3xx,status_4xx,status_5xx,
                 status_403,status_404,post_requests,sensitive_hits,wp_login_hits,bot_hits,bytes_sum,first_seen,last_seen)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT(dataset_id,ip,bucket_minute) DO UPDATE SET
                  requests=ip_minute_features.requests+EXCLUDED.requests,
                  status_2xx=ip_minute_features.status_2xx+EXCLUDED.status_2xx,
                  status_3xx=ip_minute_features.status_3xx+EXCLUDED.status_3xx,
                  status_4xx=ip_minute_features.status_4xx+EXCLUDED.status_4xx,
                  status_5xx=ip_minute_features.status_5xx+EXCLUDED.status_5xx,
                  status_403=ip_minute_features.status_403+EXCLUDED.status_403,
                  status_404=ip_minute_features.status_404+EXCLUDED.status_404,
                  post_requests=ip_minute_features.post_requests+EXCLUDED.post_requests,
                  sensitive_hits=ip_minute_features.sensitive_hits+EXCLUDED.sensitive_hits,
                  wp_login_hits=ip_minute_features.wp_login_hits+EXCLUDED.wp_login_hits,
                  bot_hits=ip_minute_features.bot_hits+EXCLUDED.bot_hits,
                  bytes_sum=ip_minute_features.bytes_sum+EXCLUDED.bytes_sum,
                  first_seen=LEAST(ip_minute_features.first_seen,EXCLUDED.first_seen),
                  last_seen=GREATEST(ip_minute_features.last_seen,EXCLUDED.last_seen)""",
                    [(dataset_id, ip, minute, *[row[key] for key in (
                    "requests", "status_2xx", "status_3xx", "status_4xx", "status_5xx", "status_403",
                    "status_404", "post_requests", "sensitive_hits", "wp_login_hits", "bot_hits", "bytes_sum",
                    "first_seen", "last_seen")]) for (ip, minute), row in buckets.items()])
    with conn.cursor() as cur:
                cur.executemany(
                """INSERT INTO ip_minute_path_seen(dataset_id,ip,bucket_minute,path,requests,status_4xx,status_5xx)
                VALUES (%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT(dataset_id,ip,bucket_minute,path) DO UPDATE SET
                  requests=ip_minute_path_seen.requests+EXCLUDED.requests,
                  status_4xx=ip_minute_path_seen.status_4xx+EXCLUDED.status_4xx,
                  status_5xx=ip_minute_path_seen.status_5xx+EXCLUDED.status_5xx""",
                    [(dataset_id, ip, minute, path, row["requests"], row["status_4xx"], row["status_5xx"])
                     for (ip, minute, path), row in paths.items()])
class PgDetectionRepository:
    """PostgreSQL-owned feature -> detection -> classification transaction."""

    @staticmethod
    def _aggregate_many(conn, dataset_id: str, ips: set[str], now: datetime) -> dict[str, tuple[dict, dict, dict]]:
        """Aggregate all windows for an ingest batch in two set-based queries."""
        values = sorted(ips)
        cut24, cut1 = now - timedelta(hours=24), now - timedelta(hours=1)
        metrics = ("requests", "status_2xx", "status_3xx", "status_4xx", "status_5xx", "post_requests", "sensitive_hits", "wp_login_hits", "bot_hits")
        metric_sql = ",\n".join(
            f"COALESCE(SUM({name}),0) AS {name}, "
            f"COALESCE(SUM({name}) FILTER (WHERE bucket_minute >= %s),0) AS recent_{name}, "
            f"COALESCE(SUM({name}) FILTER (WHERE bucket_minute >= %s),0) AS one_hour_{name}"
            for name in metrics
        )
        rows = conn.execute(
            f"""SELECT host(ip) AS ip, {metric_sql},
                       MIN(first_seen) AS first_seen, MAX(last_seen) AS last_seen,
                       MIN(first_seen) FILTER (WHERE bucket_minute >= %s) AS recent_first_seen,
                       MAX(last_seen) FILTER (WHERE bucket_minute >= %s) AS recent_last_seen,
                       MIN(first_seen) FILTER (WHERE bucket_minute >= %s) AS one_hour_first_seen,
                       MAX(last_seen) FILTER (WHERE bucket_minute >= %s) AS one_hour_last_seen
                FROM ip_minute_features
                WHERE dataset_id=%s AND ip=ANY(%s::inet[])
                GROUP BY ip""",
            [value for _name in metrics for value in (cut24, cut1)] + [cut24, cut24, cut1, cut1, dataset_id, values],
        ).fetchall()
        path_rows = conn.execute(
            """SELECT host(ip) AS ip,
                      COUNT(DISTINCT path) AS unique_paths, MAX(requests) AS peak_requests_1m,
                      COUNT(DISTINCT path) FILTER (WHERE bucket_minute >= %s) AS recent_unique_paths,
                      MAX(requests) FILTER (WHERE bucket_minute >= %s) AS recent_peak_requests_1m,
                      COUNT(DISTINCT path) FILTER (WHERE bucket_minute >= %s) AS one_hour_unique_paths,
                      MAX(requests) FILTER (WHERE bucket_minute >= %s) AS one_hour_peak_requests_1m
               FROM ip_minute_path_seen
               WHERE dataset_id=%s AND ip=ANY(%s::inet[])
               GROUP BY ip""",
            (cut24, cut24, cut1, cut1, dataset_id, values),
        ).fetchall()
        by_path = {str(row["ip"]): dict(row) for row in path_rows}

        def window(row: dict, prefix: str) -> dict:
            result = {
                "requests": int(row.get(f"{prefix}requests") or 0),
                "status_2xx": int(row.get(f"{prefix}status_2xx") or 0),
                "status_3xx": int(row.get(f"{prefix}status_3xx") or 0),
                "status_4xx": int(row.get(f"{prefix}status_4xx") or 0),
                "status_5xx": int(row.get(f"{prefix}status_5xx") or 0),
                "post_requests": int(row.get(f"{prefix}post_requests") or 0),
                "sensitive_probe_requests": int(row.get(f"{prefix}sensitive_hits") or 0),
                "wp_login_requests": int(row.get(f"{prefix}wp_login_hits") or 0),
                "bot_requests": int(row.get(f"{prefix}bot_hits") or 0),
                "unique_paths": int(row.get(f"{prefix}unique_paths") or 0),
                "peak_requests_1m": int(row.get(f"{prefix}peak_requests_1m") or 0),
            }
            result["peak_requests_5m"] = result["peak_requests_1m"]
            for name in ("first_seen", "last_seen"):
                value = row.get(f"{prefix}{name}")
                result[name] = value.isoformat() if value else None
            return result

        result: dict[str, tuple[dict, dict, dict]] = {}
        for raw in rows:
            row = dict(raw)
            row.update(by_path.get(str(row["ip"]), {}))
            result[str(row["ip"])] = (window(row, ""), window(row, "recent_"), window(row, "one_hour_"))
        return result

    @staticmethod
    def _score(row: dict[str, Any], window: str) -> tuple[int, str, list, list[dict]]:
        requests = int(row.get("requests") or 0)
        ctx = BehaviorContext(
            requests_1h=requests, requests_24h=requests,
            peak_requests_1m=int(row.get("peak_requests_1m") or 0),
            peak_requests_5m=int(row.get("peak_requests_5m") or 0),
            status_4xx_ratio_1h=(int(row.get("status_4xx") or 0) / requests if requests else 0),
            unique_paths_1h=int(row.get("unique_paths") or 0),
            sensitive_probes_1h=int(row.get("sensitive_probe_requests") or 0),
            first_seen=row.get("first_seen"), last_seen=row.get("last_seen"),
            requests=requests, status_2xx=int(row.get("status_2xx") or 0),
            status_3xx=int(row.get("status_3xx") or 0), status_4xx=int(row.get("status_4xx") or 0),
            status_5xx=int(row.get("status_5xx") or 0), unique_paths=int(row.get("unique_paths") or 0),
            wp_login_requests=int(row.get("wp_login_requests") or 0),
            sensitive_probe_requests=int(row.get("sensitive_probe_requests") or 0),
            bot_requests=int(row.get("bot_requests") or 0),
        )
        detections = run_rules(ctx, window)
        score = min(sum(item.points for item in detections), 100)
        level = "low" if score < 25 else "medium" if score < 55 else "high" if score < 80 else "critical"
        return score, level, [item.evidence for item in detections], [item.to_dict() for item in detections]

    def process_events(
        self, events: Iterable[dict[str, Any]], batch_id: str, dataset_id: str = "live",
        source_id: str | None = None, start_offset: int | None = None, end_offset: int | None = None,
        log_key: str | None = None, status: str = "live", *, now: datetime | None = None,
        failpoint=None,
    ) -> dict[str, Any]:
        events = list(events)
        finish_rules = metrics.timed("rules.evaluation_batch_ms")
        metrics.increment("rules.evaluation_batches")
        buckets, paths = _feature_deltas(events)
        if not buckets:
            return {"processed": False, "affected": set()}
        affected = {ip for ip, _ in buckets}
        received_by_ip: dict[str, str] = {}
        for event in events:
            ip = str(event.get("src_ip") or "")
            received_at = event.get("pipeline_received_at")
            if ip and received_at:
                received_by_ip[ip] = min(received_by_ip.get(ip, str(received_at)), str(received_at))
        now = now or utcnow()
        failpoint = failpoint or NoopFailpoint()
        failpoint.hit("after_parse")
        with transaction() as conn:
            inserted = conn.execute(
                """INSERT INTO processed_batches(batch_id,dataset_id,source_id,start_offset,end_offset,event_count)
                   VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT(batch_id) DO NOTHING RETURNING batch_id""",
                (batch_id, dataset_id, source_id, start_offset, end_offset, len(events)),
            ).fetchone()
            if not inserted:
                return {"processed": False, "duplicate": True, "affected": set(affected)}
            failpoint.hit("after_processed_batch_insert")
            _upsert_feature_deltas(conn, buckets, paths, dataset_id)
            failpoint.hit("after_feature_upsert")
            aggregates = self._aggregate_many(conn, dataset_id, affected, now)
            profile_rows = conn.execute(
                "SELECT * FROM ip_profiles WHERE ip=ANY(%s::inet[])", (sorted(affected),)
            ).fetchall()
            profiles = {str(row["ip"]): dict(row) for row in profile_rows}
            previous_rows = conn.execute(
                "SELECT * FROM ip_classification_state WHERE ip=ANY(%s::inet[])", (sorted(affected),)
            ).fetchall()
            previous_by_ip = {str(row["ip"]): dict(row) for row in previous_rows}
            for ip in sorted(affected):
                lifetime, recent, one_hour = aggregates[ip]
                lifetime_score, lifetime_level, lifetime_evidence, lifetime_detections = self._score(lifetime, "24h")
                one_score, _, one_evidence, one_detections = self._score(one_hour, "1h")
                recent_score, recent_level, recent_evidence, recent_detections = self._score(recent, "24h")
                payload = {
                    "ip": ip, "first_seen": lifetime.get("first_seen"), "last_seen": lifetime.get("last_seen"),
                    "requests": lifetime["requests"], "status_2xx": lifetime["status_2xx"], "status_3xx": lifetime["status_3xx"],
                    "status_4xx": lifetime["status_4xx"], "status_5xx": lifetime["status_5xx"], "unique_paths": lifetime["unique_paths"],
                    "wp_login_requests": lifetime["wp_login_requests"], "sensitive_probe_requests": lifetime["sensitive_probe_requests"],
                    "bot_requests": lifetime["bot_requests"], "behavior_score": min(lifetime_score + one_score, 100),
                    "behavior_level": lifetime_level, "behavior_evidence": lifetime_evidence + one_evidence,
                    "detections": lifetime_detections + one_detections, "detections_1h": one_detections,
                    "detections_24h": lifetime_detections, "detections_recent": recent_detections,
                    "recent_first_seen": recent.get("first_seen"), "recent_last_seen": recent.get("last_seen"),
                    "recent_requests": recent["requests"], "recent_status_2xx": recent["status_2xx"],
                    "recent_status_3xx": recent["status_3xx"], "recent_status_4xx": recent["status_4xx"],
                    "recent_status_5xx": recent["status_5xx"], "recent_unique_paths": recent["unique_paths"],
                    "recent_wp_login_requests": recent["wp_login_requests"], "recent_sensitive_probe_requests": recent["sensitive_probe_requests"],
                    "recent_bot_requests": recent["bot_requests"], "recent_behavior_score": min(recent_score, 100),
                    "recent_behavior_level": recent_level, "recent_behavior_evidence": recent_evidence,
                    "ruleset_hash": ruleset_hash(), "ruleset_hash_1h": ruleset_hash(), "ruleset_hash_24h": ruleset_hash(),
                    "evaluated_at": now.isoformat(), "evaluated_at_1h": now.isoformat(), "evaluated_at_24h": now.isoformat(),
                    "recent_updated_at": now.isoformat(), "updated_at": now.isoformat(),
                    "pipeline_received_at": received_by_ip.get(ip, now.isoformat()),
                }
                conn.execute(
                    """INSERT INTO ip_observations_state(ip,payload,ruleset_hash,updated_at) VALUES (%s,%s,%s,%s)
                       ON CONFLICT(ip) DO UPDATE SET payload=EXCLUDED.payload,ruleset_hash=EXCLUDED.ruleset_hash,updated_at=EXCLUDED.updated_at""",
                    (ip, _json(payload), payload["ruleset_hash"], now),
                )
                failpoint.hit("after_detection")
                profile = profiles.get(ip, {"ip": ip})
                classification = classify_ip(profile, payload, {}, None)
                previous = previous_by_ip.get(ip)
                old_label = previous["label"] if previous else None
                old_score = int(previous["score"]) if previous else None
                conn.execute(
                    """INSERT INTO ip_classification_state(ip,label,score,confidence,updated_at) VALUES (%s,%s,%s,%s,%s)
                       ON CONFLICT(ip) DO UPDATE SET label=EXCLUDED.label,score=EXCLUDED.score,confidence=EXCLUDED.confidence,updated_at=EXCLUDED.updated_at""",
                    (ip, classification["label"], int(classification["score"]), int(classification.get("confidence", 0)), now),
                )
                conn.execute(
                    """INSERT INTO ip_change_log(dataset_id,ip,reason,changed_at,old_label,new_label,old_score,new_score)
                       VALUES (%s,%s,'traffic',%s,%s,%s,%s,%s)""",
                    (dataset_id, ip, now, old_label, classification["label"], old_score, int(classification["score"])),
                )
                if old_label != classification["label"]:
                    conn.execute(
                        """INSERT INTO ip_change_log(dataset_id,ip,reason,changed_at,old_label,new_label,old_score,new_score)
                           VALUES (%s,%s,'classification',%s,%s,%s,%s,%s)""",
                        (dataset_id, ip, now, old_label, classification["label"], old_score, int(classification["score"])),
                    )
                failpoint.hit("after_classification")
                if classification["label"] == "bad" and old_label != "bad":
                    key = f"classification_bad:{dataset_id}:{ip}:{batch_id}"
                    conn.execute(
                        """INSERT INTO alert_outbox(ip,event_type,payload,status,attempts,next_retry_at,idempotency_key)
                           VALUES (%s,'classification_bad',%s,'pending',0,%s,%s) ON CONFLICT(idempotency_key) DO NOTHING""",
                        (ip, _json({"ip": ip, "classification": classification}), now, key),
                    )
                failpoint.hit("after_alert_outbox")
            state_ready_at = utcnow().isoformat()
            conn.execute(
                """UPDATE ip_observations_state
                   SET payload=jsonb_set(payload,'{pipeline_state_ready_at}',to_jsonb(%s::text),true)
                   WHERE ip=ANY(%s::inet[])""",
                (state_ready_at, list(affected)),
            )
            if source_id is not None and end_offset is not None:
                failpoint.hit("before_checkpoint")
                CheckpointRepository().commit_offset(
                    conn, source_id, log_key or source_id, int(end_offset), status,
                    now,
                )
                failpoint.hit("after_checkpoint")
            failpoint.hit("before_pg_commit")
        failpoint.hit("after_pg_commit")
        finish_rules()
        return {"processed": True, "duplicate": False, "affected": affected}


class StateRepository:
    """Read model for the split dashboard state APIs."""

    _sorts = {
        "threat_signal_score": "COALESCE(NULLIF(o.payload->>'recent_behavior_score','')::int, NULLIF(o.payload->>'behavior_score','')::int, 0)",
        "requests": "COALESCE(NULLIF(o.payload->>'requests','')::bigint, 0)",
        "status_4xx": "COALESCE(NULLIF(o.payload->>'status_4xx','')::bigint, 0)",
        "unique_paths": "COALESCE(NULLIF(o.payload->>'unique_paths','')::bigint, 0)",
        "last_seen": "COALESCE(NULLIF(o.payload->>'last_seen','')::timestamptz, p.fetched_at)",
    }

    @staticmethod
    def _where(q: str | None, privacy: str | None, classification: str | None, disposition: str | None) -> tuple[str, list[Any]]:
        clauses = ["TRUE"]
        args: list[Any] = []
        if q:
            term = f"%{q.strip()}%"
            clauses.append("(i.ip::text ILIKE %s OR COALESCE(p.country,'') ILIKE %s OR COALESCE(p.country_code,'') ILIKE %s OR COALESCE(p.asn,'') ILIKE %s OR COALESCE(p.organization,'') ILIKE %s)")
            args.extend([term] * 5)
        if privacy == "privacy":
            clauses.append("(COALESCE(p.is_tor,FALSE) OR COALESCE(p.is_vpn,FALSE) OR COALESCE(p.is_proxy,FALSE))")
        elif privacy == "tor":
            clauses.append("COALESCE(p.is_tor,FALSE)")
        elif privacy == "hosting":
            clauses.append("COALESCE(p.is_hosting,FALSE)")
        if classification:
            clauses.append("COALESCE(cs.label,'unknown')=%s")
            args.append(classification)
        if disposition:
            clauses.append("COALESCE(d.state,'new')=%s")
            args.append(disposition)
        return " AND ".join(clauses), args

    def page(self, page: int, page_size: int, sort: str, direction: str, q: str | None = None,
             privacy: str | None = None, classification: str | None = None, disposition: str | None = None) -> dict[str, Any]:
        where, args = self._where(q, privacy, classification, disposition)
        order = self._sorts.get(sort, self._sorts["threat_signal_score"])
        order_direction = "ASC" if direction.lower() == "asc" else "DESC"
        with transaction() as conn:
            total = conn.execute(
                f"""WITH identities AS (SELECT ip FROM ip_observations_state UNION SELECT ip FROM ip_profiles)
                    SELECT COUNT(*) AS n FROM identities i
                    LEFT JOIN ip_observations_state o ON o.ip=i.ip
                    LEFT JOIN ip_profiles p ON p.ip=i.ip
                    LEFT JOIN ip_classification_state cs ON cs.ip=i.ip
                    LEFT JOIN ip_dispositions d ON d.ip=i.ip WHERE {where}""", args,
            ).fetchone()["n"]
            rows = conn.execute(
                f"""WITH identities AS (SELECT ip FROM ip_observations_state UNION SELECT ip FROM ip_profiles)
                    SELECT host(i.ip) AS identity_ip, p.*, o.payload AS observation_payload,
                           cs.label, cs.score AS classification_score, cs.confidence AS classification_confidence,
                           d.state AS disposition
                      FROM identities i
                      LEFT JOIN ip_observations_state o ON o.ip=i.ip
                      LEFT JOIN ip_profiles p ON p.ip=i.ip
                      LEFT JOIN ip_classification_state cs ON cs.ip=i.ip
                      LEFT JOIN ip_dispositions d ON d.ip=i.ip
                     WHERE {where}
                     ORDER BY {order} {order_direction}, COALESCE(NULLIF(o.payload->>'requests','')::bigint,0) DESC, i.ip ASC
                     LIMIT %s OFFSET %s""", [*args, page_size, (page - 1) * page_size],
            ).fetchall()
            cursor = conn.execute("SELECT COALESCE(MAX(seq),0) AS seq FROM ip_change_log").fetchone()["seq"]
        normalized = []
        for row in rows:
            item = dict(row)
            item["ip"] = str(item.pop("identity_ip"))
            normalized.append(item)
        return {"rows": normalized, "total": int(total or 0), "cursor": int(cursor or 0)}

    def summary(self) -> dict[str, Any]:
        with transaction() as conn:
            row = conn.execute("""WITH identities AS (SELECT ip FROM ip_observations_state UNION SELECT ip FROM ip_profiles)
                SELECT COUNT(*) total,
                  COUNT(*) FILTER (WHERE COALESCE(cs.label,'unknown')='bad') bad,
                  COUNT(*) FILTER (WHERE COALESCE(cs.label,'unknown')='watch') watch,
                  COUNT(*) FILTER (WHERE COALESCE(cs.label,'unknown')='good') good,
                  COUNT(*) FILTER (WHERE COALESCE(cs.label,'unknown')='unknown') unknown,
                  COUNT(*) FILTER (WHERE COALESCE(p.is_tor,FALSE) OR COALESCE(p.is_vpn,FALSE) OR COALESCE(p.is_proxy,FALSE)) privacy
                FROM identities i LEFT JOIN ip_classification_state cs ON cs.ip=i.ip LEFT JOIN ip_profiles p ON p.ip=i.ip""").fetchone()
            priority = conn.execute("""SELECT host(i.ip) AS ip FROM ip_classification_state cs
                JOIN (SELECT ip FROM ip_observations_state UNION SELECT ip FROM ip_profiles) i ON i.ip=cs.ip
                LEFT JOIN ip_dispositions d ON d.ip=cs.ip
                WHERE cs.label IN ('bad','watch') AND COALESCE(d.state, 'new') != 'resolved'
                ORDER BY cs.score DESC, i.ip ASC LIMIT 5""").fetchall()
        return {"total_ips": int(row["total"] or 0), "classification": {k: int(row[k] or 0) for k in ("bad","watch","good","unknown")}, "privacy": {"total": int(row["privacy"] or 0)}, "priority_ips": [str(r["ip"]) for r in priority]}


    def get(self, ip: str) -> dict[str, Any] | None:
        rows = self.get_many([ip])
        return rows[0] if rows else None

    def get_many(self, ips: Iterable[str]) -> list[dict[str, Any]]:
        values = tuple(dict.fromkeys(str(ip) for ip in ips))
        if not values:
            return []
        with transaction() as conn:
            rows = conn.execute("""SELECT host(i.ip) AS identity_ip,p.*,o.payload AS observation_payload,
                cs.label,cs.score AS classification_score,cs.confidence AS classification_confidence,
                d.state AS disposition, d.suggested_state, d.assigned_to, d.note, d.updated_at AS disposition_updated_at, d.history AS disposition_history
                FROM (SELECT ip FROM ip_observations_state UNION SELECT ip FROM ip_profiles) i
                LEFT JOIN ip_profiles p ON p.ip=i.ip LEFT JOIN ip_observations_state o ON o.ip=i.ip
                LEFT JOIN ip_classification_state cs ON cs.ip=i.ip LEFT JOIN ip_dispositions d ON d.ip=i.ip
                WHERE i.ip = ANY(%s::inet[])""", (list(values),)).fetchall()

        normalized = []
        for row in rows:
            item = dict(row)
            item["ip"] = str(item.pop("identity_ip"))
            normalized.append(item)
        by_ip = {item["ip"]: item for item in normalized}
        return [by_ip[ip] for ip in values if ip in by_ip]

    def changes(self, after: int, limit: int) -> dict[str, Any]:
        with transaction() as conn:
            current = int(conn.execute("SELECT COALESCE(MAX(seq),0) AS n FROM ip_change_log").fetchone()["n"] or 0)
            oldest = int(conn.execute("SELECT COALESCE(MIN(seq),0) AS n FROM ip_change_log").fetchone()["n"] or 0)
            if after and oldest and after < oldest - 1:
                return {"current": current, "reset_required": True, "rows": []}
            rows = conn.execute("SELECT seq,host(ip) AS ip,reason,old_label,new_label,old_score,new_score,changed_at FROM ip_change_log WHERE seq>%s ORDER BY seq LIMIT %s", (after, limit + 1)).fetchall()
        return {"current": current, "reset_required": False, "rows": [dict(r) for r in rows[:limit]], "has_more": len(rows) > limit}


class CheckpointRepository:
    """PostgreSQL source offset and collector lease state."""

    def load_offset(self, source_id: str, log_key: str) -> int:
        with transaction() as conn:
            row = conn.execute("SELECT last_offset FROM log_sources WHERE source_id=%s", (source_id,)).fetchone()
            if not row:
                conn.execute("INSERT INTO log_sources(source_id,log_key,status) VALUES (%s,%s,'starting')", (source_id, log_key))
                return 0
            return int(row["last_offset"] or 0)

    def status(self, source_id: str, log_key: str, state: str, error: str | None = None) -> None:
        with transaction() as conn:
            conn.execute("""INSERT INTO log_sources(source_id,log_key,status,last_error,updated_at)
                VALUES (%s,%s,%s,%s,now()) ON CONFLICT(source_id) DO UPDATE SET log_key=EXCLUDED.log_key,status=EXCLUDED.status,last_error=EXCLUDED.last_error,updated_at=now()""", (source_id, log_key, state, error))

    def acquire(self, source_id: str, log_key: str, owner: str, state: str) -> bool:
        now = datetime.now(timezone.utc)
        expires = now + timedelta(seconds=30)
        with transaction() as conn:
            conn.execute("""INSERT INTO log_sources(source_id,log_key,status,lease_owner,lease_expires_at,updated_at)
                VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT(source_id) DO UPDATE SET log_key=EXCLUDED.log_key,status=EXCLUDED.status,lease_owner=EXCLUDED.lease_owner,lease_expires_at=EXCLUDED.lease_expires_at,updated_at=EXCLUDED.updated_at
                WHERE log_sources.lease_owner=EXCLUDED.lease_owner OR log_sources.lease_expires_at IS NULL OR log_sources.lease_expires_at < EXCLUDED.updated_at""", (source_id, log_key, state, owner, expires, now))
            row = conn.execute("SELECT lease_owner FROM log_sources WHERE source_id=%s", (source_id,)).fetchone()
        return bool(row and row["lease_owner"] == owner)

    def renew(self, source_id: str, owner: str) -> None:
        with transaction() as conn:
            conn.execute("UPDATE log_sources SET lease_expires_at=%s,updated_at=%s WHERE source_id=%s AND lease_owner=%s", (datetime.now(timezone.utc) + timedelta(seconds=30), datetime.now(timezone.utc), source_id, owner))

    def commit_offset(self, conn, source_id: str, log_key: str, offset: int, state: str, event_at: datetime | None) -> None:
        conn.execute("""INSERT INTO log_sources(source_id,log_key,last_offset,status,last_event_at,updated_at)
            VALUES (%s,%s,%s,%s,%s,now()) ON CONFLICT(source_id) DO UPDATE SET log_key=EXCLUDED.log_key,last_offset=EXCLUDED.last_offset,status=EXCLUDED.status,last_event_at=COALESCE(EXCLUDED.last_event_at,log_sources.last_event_at),updated_at=now()""", (source_id, log_key, offset, state, event_at))


class DispositionRepository:
    def set(self, ip: str, state: str, assigned_to: str | None, note: str | None, actor: str, label: str | None) -> dict[str, Any]:
        suggestion = {"bad": "investigate", "watch": "monitor"}.get(label)
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


class RegionRepository:
    def seed(self, items: list[dict[str, Any]]) -> None:
        with transaction() as conn:
            for item in items:
                if not item.get("country_code") or not item.get("country_name"):
                    raise ValueError("region seed item missing country identity")
                conn.execute(
                    """INSERT INTO region_profiles
                       (country_code,country_name,economic_indicators,cultural_context,
                        conflict_indicators,sources,observed_ip_count,updated_at)
                       VALUES (%s,%s,%s,%s,%s,%s,COALESCE((SELECT observed_ip_count FROM region_profiles WHERE country_code = %s), 0),%s)
                       ON CONFLICT(country_code) DO UPDATE SET
                         country_name=EXCLUDED.country_name,
                         economic_indicators=EXCLUDED.economic_indicators,
                         cultural_context=EXCLUDED.cultural_context,
                         conflict_indicators=EXCLUDED.conflict_indicators,
                         sources=EXCLUDED.sources,
                         updated_at=EXCLUDED.updated_at""",
                    (
                        item["country_code"],
                        item["country_name"],
                        _json(normalise_economic_indicators(item.get("economic_indicators"))),
                        _json(item.get("cultural_context")),
                        _json(normalise_conflict_indicators(item.get("conflict_indicators"))),
                        _json(item.get("sources")),
                        item["country_code"],
                        item.get("updated_at") or "",
                    )
                )

    def get(self, country_code: str | None) -> dict[str, Any] | None:
        if not country_code:
            return None
        with transaction() as conn:
            row = conn.execute("SELECT * FROM region_profiles WHERE country_code = %s", (country_code.upper(),)).fetchone()
            if not row:
                return None
            data = dict(row)
            data["economic_indicators"] = normalise_economic_indicators(_decode_json(data["economic_indicators"]))
            data["cultural_context"] = _decode_json(data["cultural_context"]) or []
            data["conflict_indicators"] = normalise_conflict_indicators(_decode_json(data["conflict_indicators"]))
            data["sources"] = _decode_json(data["sources"]) or []
            observed = conn.execute("SELECT COUNT(*) AS n FROM ip_profiles WHERE country_code = %s", (country_code.upper(),)).fetchone()
            data["observed_ip_count"] = observed["n"] if observed else data.get("observed_ip_count", 0)
            data.update(market_score(data))
            return data

    def list(self, limit: int = 50) -> list[dict[str, Any]]:
        with transaction() as conn:
            rows = conn.execute("SELECT country_code FROM region_profiles ORDER BY country_name ASC LIMIT %s", (limit,)).fetchall()
        return [self.get(row["country_code"]) for row in rows if row["country_code"]]

    def demand_signal(self, limit: int = 50) -> list[dict[str, Any]]:
        with transaction() as conn:
            rows = conn.execute("""
                SELECT p.*, o.payload AS observation_payload, cs.label AS classification_label
                FROM ip_profiles p
                LEFT JOIN ip_observations_state o ON o.ip = p.ip
                LEFT JOIN ip_classification_state cs ON cs.ip = p.ip
                WHERE p.country_code IS NOT NULL
            """).fetchall()
        
        aggregates = {}
        for raw in rows:
            item = dict(raw)
            for key in ("identity_evidence", "reputation", "evidence", "sources"):
                item[key] = _decode_json(item.get(key)) or []
            
            obs_payload = item.get("observation_payload") or {}
            label = item.get("classification_label") or "unknown"
            code = item["country_code"]
            
            if code not in aggregates:
                region = self.get(code) or {
                    "country_code": code,
                    "country_name": item.get("country") or code,
                }
                aggregates[code] = {
                    "country_code": code,
                    "country_name": region.get("country_name") or item.get("country") or code,
                    "observed_ip_count": 0,
                    "observed_requests": 0,
                    "good_ip_count": 0,
                    "classified_good_ip_count": 0,
                    "good_requests": 0,
                    "watch_ip_count": 0,
                    "bad_ip_count": 0,
                    "unknown_ip_count": 0,
                    "privacy_signal_ip_count": 0,
                    "profile_updated_at": region.get("updated_at"),
                    "economic_indicators": region.get("economic_indicators", {}),
                    "market_components": region.get("market_components", {}),
                    "market_score": region.get("market_score"),
                    "market_level": region.get("market_level", "unknown"),
                    "product_opportunities": region.get("product_opportunities", []),
                    "cultural_context": region.get("cultural_context", []),
                    "conflict_indicators": region.get("conflict_indicators", []),
                    "sources": region.get("sources", []),
                }
            
            entry = aggregates[code]
            requests = int(obs_payload.get("requests") or 0)
            
            entry["observed_ip_count"] += 1
            entry["observed_requests"] += requests
            if label == "good":
                entry["classified_good_ip_count"] += 1
            else:
                entry[f"{label}_ip_count"] += 1
                
            privacy_signal = any(item.get(field) is True or item.get(field) == 1 for field in ("is_tor", "is_vpn", "is_proxy", "is_hosting"))
            if privacy_signal:
                entry["privacy_signal_ip_count"] += 1
            
            eligible = (
                label == "good" and requests > 0 and not privacy_signal
                and int(obs_payload.get("sensitive_probe_requests") or 0) == 0
                and int(obs_payload.get("bot_requests") or 0) == 0
            )
            if eligible:
                entry["good_requests"] += requests
                entry["good_ip_count"] += 1

        results = []
        for entry in aggregates.values():
            total = entry["observed_requests"]
            good_ips = entry["good_ip_count"]
            entry["good_traffic_share"] = round(entry["good_requests"] / total, 4) if total else 0
            entry["signal_level"] = (
                "high" if entry["good_requests"] >= 500 else
                "medium" if entry["good_requests"] >= 50 else
                "low" if entry["good_requests"] > 0 else "none"
            )
            entry["product_demand"] = (entry.get("market_components") or {}).get("product_demand")
            entry["analyst_note"] = "Observed good traffic signal; validate with conversion and customer data before market decisions." if good_ips else "No qualifying good traffic observed in the current window."
            results.append(entry)
        
        results.sort(key=lambda x: (x["good_requests"], x["observed_requests"]), reverse=True)
        return results[:limit]
