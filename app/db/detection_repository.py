"""PostgreSQL feature aggregation and detection transaction persistence."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from .alert_repository import _alert_evidence_for_classification, persist_classification_alert_and_notification
from .checkpoints import CheckpointRepository
from .classification_history_repository import ClassificationHistoryRepository
from .json_codec import jsonb_value as _json
from .postgres import transaction
from ..core.clock import utcnow
from ..core.failpoints import NoopFailpoint
from ..core import metrics
from ..core.classification_provenance import classification_input_provenance
from ..core.intelligence import classify_ip
from ..core.path_canonicalization import canonicalize_path
from ..core.rules import BehaviorContext, run_rules, ruleset_hash
from ..core.security_markers import match_security_marker


def _feature_deltas(events: Iterable[dict[str, Any]]) -> tuple[dict, dict]:
    """Aggregate parsed requests into per-minute and per-path deltas."""
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
            path = canonicalize_path(str(event.get("path") or ""))
            ua = str(event.get("user_agent") or "").lower()
            row["requests"] += 1
            row["status_2xx"] += int(200 <= status < 300)
            row["status_3xx"] += int(300 <= status < 400)
            row["status_4xx"] += int(400 <= status < 500)
            row["status_5xx"] += int(status >= 500)
            row["status_403"] += int(status == 403)
            row["status_404"] += int(status == 404)
            row["post_requests"] += int(str(event.get("method") or "").upper() == "POST")
            row["sensitive_hits"] += int(match_security_marker(path) is not None)
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


def _utc_minute(value: datetime | str) -> datetime:
    """Normalize a timestamp to its UTC minute bucket."""
    if isinstance(value, datetime):
        stamp = value
    else:
        stamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp.astimezone(timezone.utc).replace(second=0, microsecond=0)


def _rolling_peak_5m(rows: Iterable[dict[str, Any]], start: datetime | None = None) -> int:
    """Return the maximum request total in any rolling five-minute window."""
    by_minute: dict[datetime, int] = {}
    for row in rows:
        minute = _utc_minute(row["bucket_minute"])
        if start is not None and minute < start:
            continue
        by_minute[minute] = by_minute.get(minute, 0) + int(row.get("requests") or 0)

    points = sorted(by_minute.items())
    left = 0
    total = 0
    peak = 0
    for right, (minute, requests) in enumerate(points):
        total += requests
        while points[left][0] < minute - timedelta(minutes=4):
            total -= points[left][1]
            left += 1
        peak = max(peak, total)
    return peak


def _rolling_peaks_by_ip(rows: Iterable[dict[str, Any]], cut24: datetime, cut1: datetime) -> dict[str, dict[str, int]]:
    """Calculate lifetime, recent, and hourly request peaks per IP."""
    by_ip: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_ip.setdefault(str(row["ip"]), []).append(row)
    return {
        ip: {
            "peak_requests_1m": max((int(item.get("requests") or 0) for item in items), default=0),
            "recent_peak_requests_1m": max((int(item.get("requests") or 0) for item in items
                                             if _utc_minute(item["bucket_minute"]) >= cut24), default=0),
            "one_hour_peak_requests_1m": max((int(item.get("requests") or 0) for item in items
                                               if _utc_minute(item["bucket_minute"]) >= cut1), default=0),
            "peak_requests_5m": _rolling_peak_5m(items, cut24),
            "recent_peak_requests_5m": _rolling_peak_5m(items, cut24),
            "one_hour_peak_requests_5m": _rolling_peak_5m(items, cut1),
        }
        for ip, items in by_ip.items()
    }


def _select_recent_behavior_window(
    one_score: int, one_level: str, one_evidence: list, one_detections: list[dict],
    recent_score: int, recent_level: str, recent_evidence: list, recent_detections: list[dict],
) -> tuple[int, str, list, list[dict]]:
    """Use the strongest active short window as the persisted recent verdict."""
    if one_score > recent_score:
        return one_score, one_level, one_evidence, one_detections
    return recent_score, recent_level, recent_evidence, recent_detections


def _build_recent_behavior_fields(
    one_score: int, one_level: str, one_evidence: list, one_detections: list[dict],
    recent24_score: int, recent24_level: str, recent24_evidence: list, recent24_detections: list[dict],
) -> dict[str, Any]:
    """Select the strongest recent verdict and shape persisted behavior fields."""
    selected_score, selected_level, selected_evidence, selected_detections = _select_recent_behavior_window(
        one_score, one_level, one_evidence, one_detections,
        recent24_score, recent24_level, recent24_evidence, recent24_detections,
    )
    return {
        "detections_24h": recent24_detections,
        "detections_recent": selected_detections,
        "recent_behavior_score": min(selected_score, 100),
        "recent_behavior_level": selected_level,
        "recent_behavior_evidence": selected_evidence,
    }


def _upsert_feature_deltas(conn, buckets: dict, paths: dict, dataset_id: str) -> None:
    """Apply batched minute and path counters inside the caller's transaction."""
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
    def _load_minute_aggregates(conn, dataset_id, ips, cut24, cut1):
        """Load lifetime, recent and one-hour request metrics for each IP."""
        metrics = ("requests", "status_2xx", "status_3xx", "status_4xx", "status_5xx", "post_requests", "sensitive_hits", "wp_login_hits", "bot_hits")
        metric_sql = ",\n".join(
            f"COALESCE(SUM({name}),0) AS {name}, "
            f"COALESCE(SUM({name}) FILTER (WHERE bucket_minute >= %s),0) AS recent_{name}, "
            f"COALESCE(SUM({name}) FILTER (WHERE bucket_minute >= %s),0) AS one_hour_{name}"
            for name in metrics
        )
        return conn.execute(
            f"""SELECT host(ip) AS ip, {metric_sql},
                       MIN(first_seen) AS first_seen, MAX(last_seen) AS last_seen,
                       MIN(first_seen) FILTER (WHERE bucket_minute >= %s) AS recent_first_seen,
                       MAX(last_seen) FILTER (WHERE bucket_minute >= %s) AS recent_last_seen,
                       MIN(first_seen) FILTER (WHERE bucket_minute >= %s) AS one_hour_first_seen,
                       MAX(last_seen) FILTER (WHERE bucket_minute >= %s) AS one_hour_last_seen
                FROM ip_minute_features
                WHERE dataset_id=%s AND ip=ANY(%s::inet[])
                GROUP BY ip""",
            [value for _name in metrics for value in (cut24, cut1)] + [cut24, cut24, cut1, cut1, dataset_id, ips],
        ).fetchall()

    @staticmethod
    def _load_path_aggregates(conn, dataset_id, ips, cut24, cut1):
        """Load distinct-path counts for lifetime, recent and one-hour windows."""
        return conn.execute(
            """SELECT host(ip) AS ip,
                      COUNT(DISTINCT path) AS unique_paths, MAX(requests) AS peak_requests_1m,
                      COUNT(DISTINCT path) FILTER (WHERE bucket_minute >= %s) AS recent_unique_paths,
                      MAX(requests) FILTER (WHERE bucket_minute >= %s) AS recent_peak_requests_1m,
                      COUNT(DISTINCT path) FILTER (WHERE bucket_minute >= %s) AS one_hour_unique_paths,
                      MAX(requests) FILTER (WHERE bucket_minute >= %s) AS one_hour_peak_requests_1m
               FROM ip_minute_path_seen
               WHERE dataset_id=%s AND ip=ANY(%s::inet[])
               GROUP BY ip""",
            (cut24, cut24, cut1, cut1, dataset_id, ips),
        ).fetchall()

    @staticmethod
    def _load_peak_aggregates(conn, dataset_id, ips, cut24, cut1):
        """Load one-minute and rolling five-minute peaks for each time window."""
        return conn.execute(
            """WITH rolling AS (
                   SELECT host(ip) AS ip, bucket_minute, requests,
                          SUM(requests) OVER (
                            PARTITION BY ip ORDER BY bucket_minute
                            RANGE BETWEEN INTERVAL '4 minutes' PRECEDING AND CURRENT ROW
                          ) AS rolling_5m
                     FROM ip_minute_features
                    WHERE dataset_id=%s AND ip=ANY(%s::inet[]) AND bucket_minute >= %s
                 )
                 SELECT ip,
                        MAX(requests) AS peak_requests_1m,
                        MAX(requests) FILTER (WHERE bucket_minute >= %s) AS recent_peak_requests_1m,
                        MAX(requests) FILTER (WHERE bucket_minute >= %s) AS one_hour_peak_requests_1m,
                        MAX(rolling_5m) AS peak_requests_5m,
                        MAX(rolling_5m) FILTER (WHERE bucket_minute >= %s) AS recent_peak_requests_5m,
                        MAX(rolling_5m) FILTER (WHERE bucket_minute >= %s) AS one_hour_peak_requests_5m
                   FROM rolling GROUP BY ip""",
            (dataset_id, ips, cut24, cut24, cut1, cut24, cut1),
        ).fetchall()

    @staticmethod
    def _project_detection_window(row: dict[str, Any], prefix: str) -> dict[str, Any]:
        """Project joined aggregate columns into the detector window contract."""
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
            "peak_requests_5m": int(row.get(f"{prefix}peak_requests_5m") or 0),
        }
        for name in ("first_seen", "last_seen"):
            value = row.get(f"{prefix}{name}")
            result[name] = value.isoformat() if value else None
        return result

    @staticmethod
    def _aggregate_many(conn, dataset_id: str, ips: set[str], now: datetime) -> dict[str, tuple[dict, dict, dict]]:
        """Assemble lifetime, recent and one-hour aggregates for an ingest batch."""
        values = sorted(ips)
        cut24, cut1 = now - timedelta(hours=24), now - timedelta(hours=1)
        rows = PgDetectionRepository._load_minute_aggregates(conn, dataset_id, values, cut24, cut1)
        path_rows = PgDetectionRepository._load_path_aggregates(conn, dataset_id, values, cut24, cut1)
        peak_rows = PgDetectionRepository._load_peak_aggregates(conn, dataset_id, values, cut24, cut1)
        by_path = {str(row["ip"]): dict(row) for row in path_rows}
        by_peak = {str(row["ip"]): dict(row) for row in peak_rows}
        result = {}
        for raw in rows:
            row = dict(raw)
            row.update(by_path.get(str(row["ip"]), {}))
            row.update(by_peak.get(str(row["ip"]), {}))
            result[str(row["ip"])] = tuple(
                PgDetectionRepository._project_detection_window(row, prefix)
                for prefix in ("", "recent_", "one_hour_")
            )
        return result

    @staticmethod
    def _score(row: dict[str, Any], window: str) -> tuple[int, str, list, list[dict]]:
        """Run deterministic behavior rules and return their score and evidence."""
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

    @classmethod
    def _build_observation_payload(
        cls,
        ip: str,
        lifetime: dict[str, Any],
        recent: dict[str, Any],
        one_hour: dict[str, Any],
        now: datetime,
        pipeline_received_at: str,
    ) -> dict[str, Any]:
        """Build the persisted observation from lifetime and recent detection windows."""
        lifetime_score, lifetime_level, lifetime_evidence, lifetime_detections = cls._score(lifetime, "24h")
        one_score, one_level, one_evidence, one_detections = cls._score(one_hour, "1h")
        recent_score, recent_level, recent_evidence, recent_detections = cls._score(recent, "24h")
        recent_fields = _build_recent_behavior_fields(
            one_score, one_level, one_evidence, one_detections,
            recent_score, recent_level, recent_evidence, recent_detections,
        )
        return {
            "ip": ip,
            "first_seen": lifetime.get("first_seen"),
            "last_seen": lifetime.get("last_seen"),
            "requests": lifetime["requests"],
            "status_2xx": lifetime["status_2xx"],
            "status_3xx": lifetime["status_3xx"],
            "status_4xx": lifetime["status_4xx"],
            "status_5xx": lifetime["status_5xx"],
            "unique_paths": lifetime["unique_paths"],
            "wp_login_requests": lifetime["wp_login_requests"],
            "sensitive_probe_requests": lifetime["sensitive_probe_requests"],
            "bot_requests": lifetime["bot_requests"],
            "behavior_score": min(lifetime_score + one_score, 100),
            "behavior_level": lifetime_level,
            "behavior_evidence": lifetime_evidence + one_evidence,
            "detections": lifetime_detections + one_detections,
            "detections_1h": one_detections,
            **recent_fields,
            "recent_first_seen": recent.get("first_seen"),
            "recent_last_seen": recent.get("last_seen"),
            "recent_requests": recent["requests"],
            "recent_status_2xx": recent["status_2xx"],
            "recent_status_3xx": recent["status_3xx"],
            "recent_status_4xx": recent["status_4xx"],
            "recent_status_5xx": recent["status_5xx"],
            "recent_unique_paths": recent["unique_paths"],
            "recent_wp_login_requests": recent["wp_login_requests"],
            "recent_sensitive_probe_requests": recent["sensitive_probe_requests"],
            "recent_bot_requests": recent["bot_requests"],
            "ruleset_hash": ruleset_hash(),
            "ruleset_hash_1h": ruleset_hash(),
            "ruleset_hash_24h": ruleset_hash(),
            "evaluated_at": now.isoformat(),
            "evaluated_at_1h": now.isoformat(),
            "evaluated_at_24h": now.isoformat(),
            "recent_updated_at": now.isoformat(),
            "updated_at": now.isoformat(),
            "pipeline_received_at": pipeline_received_at,
        }

    @staticmethod
    def _load_classification_context(conn, affected: set[str]) -> tuple[dict[str, dict], dict[str, dict]]:
        """Load existing profiles and verdicts needed to classify affected IPs."""
        values = sorted(affected)
        profile_rows = conn.execute(
            "SELECT * FROM ip_profiles WHERE ip=ANY(%s::inet[])", (values,)
        ).fetchall()
        previous_rows = conn.execute(
            "SELECT * FROM ip_classification_state WHERE ip=ANY(%s::inet[])", (values,)
        ).fetchall()
        return (
            {str(row["ip"]): dict(row) for row in profile_rows},
            {str(row["ip"]): dict(row) for row in previous_rows},
        )

    @staticmethod
    def _persist_ip_detection(
        conn,
        *,
        dataset_id: str,
        batch_id: str,
        ip: str,
        payload: dict[str, Any],
        profile: dict[str, Any],
        previous: dict[str, Any] | None,
        now: datetime,
        failpoint,
    ) -> None:
        """Persist one IP observation, classification, change events, and alert."""
        region_profile = {}
        ai_profile = None
        from ..services.classification import classify_with_rollout_metrics

        classification = classify_with_rollout_metrics(
            profile, payload, region_profile, ai_profile, classifier=classify_ip
        )
        input_provenance = classification_input_provenance(
            profile, payload, region_profile, ai_profile
        )
        conn.execute(
            """INSERT INTO ip_observations_state(ip,payload,ruleset_hash,updated_at) VALUES (%s,%s,%s,%s)
               ON CONFLICT(ip) DO UPDATE SET payload=EXCLUDED.payload,ruleset_hash=EXCLUDED.ruleset_hash,updated_at=EXCLUDED.updated_at""",
            (ip, _json(payload), payload["ruleset_hash"], now),
        )
        failpoint.hit("after_detection")
        old_label = previous["label"] if previous else None
        old_score = int(previous["score"]) if previous else None
        conn.execute(
            """INSERT INTO ip_classification_state
               (ip,label,score,confidence,input_contract_version,input_fingerprint,updated_at)
               VALUES (%s,%s,%s,%s,%s,%s,%s)
               ON CONFLICT(ip) DO UPDATE SET label=EXCLUDED.label,score=EXCLUDED.score,
                confidence=EXCLUDED.confidence,
                input_contract_version=EXCLUDED.input_contract_version,
                input_fingerprint=EXCLUDED.input_fingerprint,updated_at=EXCLUDED.updated_at""",
            (
                ip, classification["label"], int(classification["score"]),
                int(classification.get("confidence", 0)), input_provenance["version"],
                input_provenance["fingerprint"], now,
            ),
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
            ClassificationHistoryRepository.record_transition(
                conn,
                event_key=f"traffic:{dataset_id}:{batch_id}:{ip}",
                dataset_id=dataset_id,
                ip=ip,
                source="traffic",
                changed_at=now,
                previous_classification={"label": old_label or "unknown", "score": old_score},
                current_classification=classification,
            )
        failpoint.hit("after_classification")
        alert_result = persist_classification_alert_and_notification(
            conn,
            dataset_id=dataset_id,
            batch_id=batch_id,
            ip=ip,
            old_label=old_label,
            old_score=old_score,
            classification=classification,
            evidence=_alert_evidence_for_classification(classification, payload),
            created_at=now,
            recurrence_observed_at=payload.get("recent_last_seen"),
        )
        # Import through the compatibility facade only at runtime to avoid a
        # module cycle with PgDetectionRepository's existing re-export.
        from .repositories import DispositionRepository

        DispositionRepository.apply_automatic_transition(
            conn,
            ip=ip,
            classification_label=classification.get("label"),
            alert_result=alert_result,
            now=now,
        )
        failpoint.hit("after_alert_outbox")

    @staticmethod
    def _mark_pipeline_state_ready(conn, affected: set[str]) -> None:
        """Record when all persisted observations in the batch became queryable."""
        conn.execute(
            """UPDATE ip_observations_state
               SET payload=jsonb_set(payload,'{pipeline_state_ready_at}',to_jsonb(%s::text),true)
               WHERE ip=ANY(%s::inet[])""",
            (utcnow().isoformat(), sorted(affected)),
        )

    @staticmethod
    def _commit_source_offset(
        conn,
        *,
        source_id: str | None,
        end_offset: int | None,
        log_key: str | None,
        status: str,
        now: datetime,
        owner: str | None,
        failpoint,
    ) -> None:
        """Commit the source checkpoint inside the detection transaction."""
        if source_id is None or end_offset is None:
            return
        if not owner:
            raise ValueError("owner is required when committing a source checkpoint")
        failpoint.hit("before_checkpoint")
        CheckpointRepository().commit_offset(conn, source_id, log_key or source_id, int(end_offset), status, now, owner)
        failpoint.hit("after_checkpoint")

    @staticmethod
    def _received_at_by_ip(events: list[dict[str, Any]]) -> dict[str, str]:
        """Keep the earliest pipeline-received timestamp for each source IP."""
        received_by_ip: dict[str, str] = {}
        for event in events:
            ip = str(event.get("src_ip") or "")
            received_at = event.get("pipeline_received_at")
            if ip and received_at:
                received_by_ip[ip] = min(received_by_ip.get(ip, str(received_at)), str(received_at))
        return received_by_ip

    def _persist_affected_ip_states(
        self, conn, dataset_id, batch_id, affected, received_by_ip, now, failpoint
    ) -> None:
        """Aggregate and persist detection state for every affected IP."""
        aggregates = self._aggregate_many(conn, dataset_id, affected, now)
        profiles, previous_by_ip = self._load_classification_context(conn, affected)
        for ip in sorted(affected):
            lifetime, recent, one_hour = aggregates[ip]
            payload = self._build_observation_payload(
                ip, lifetime, recent, one_hour, now, received_by_ip.get(ip, now.isoformat())
            )
            self._persist_ip_detection(
                conn,
                dataset_id=dataset_id,
                batch_id=batch_id,
                ip=ip,
                payload=payload,
                profile=profiles.get(ip, {"ip": ip}),
                previous=previous_by_ip.get(ip),
                now=now,
                failpoint=failpoint,
            )

    def _apply_detection_transaction(
        self, events, batch_id, dataset_id, source_id, start_offset, end_offset,
        log_key, status, buckets, paths, affected, received_by_ip, now, owner, failpoint,
    ) -> bool:
        """Persist batch identity, features, detections, and checkpoint atomically."""
        with transaction() as conn:
            inserted = conn.execute(
                """INSERT INTO processed_batches(batch_id,dataset_id,source_id,start_offset,end_offset,event_count)
                   VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT(batch_id) DO NOTHING RETURNING batch_id""",
                (batch_id, dataset_id, source_id, start_offset, end_offset, len(events)),
            ).fetchone()
            if not inserted:
                return False
            failpoint.hit("after_processed_batch_insert")
            _upsert_feature_deltas(conn, buckets, paths, dataset_id)
            failpoint.hit("after_feature_upsert")
            self._persist_affected_ip_states(
                conn, dataset_id, batch_id, affected, received_by_ip, now, failpoint
            )
            self._mark_pipeline_state_ready(conn, affected)
            self._commit_source_offset(
                conn,
                source_id=source_id,
                end_offset=end_offset,
                log_key=log_key,
                status=status,
                now=now,
                owner=owner,
                failpoint=failpoint,
            )
            failpoint.hit("before_pg_commit")
        failpoint.hit("after_pg_commit")
        return True

    def process_events(
        self, events: Iterable[dict[str, Any]], batch_id: str, dataset_id: str = "live",
        source_id: str | None = None, start_offset: int | None = None, end_offset: int | None = None,
        log_key: str | None = None, status: str = "live", *, now: datetime | None = None,
        owner: str | None = None, failpoint=None,
    ) -> dict[str, Any]:
        """Measure and process one idempotent PostgreSQL detection batch."""
        finish = metrics.timed("rules.evaluation_batch_ms")
        try:
            return self._process_events(
                events, batch_id, dataset_id, source_id, start_offset, end_offset,
                log_key, status, now=now, owner=owner, failpoint=failpoint,
            )
        finally:
            finish()

    def _process_events(
        self, events: Iterable[dict[str, Any]], batch_id: str, dataset_id: str = "live",
        source_id: str | None = None, start_offset: int | None = None, end_offset: int | None = None,
        log_key: str | None = None, status: str = "live", *, now: datetime | None = None,
        owner: str | None = None, failpoint=None,
    ) -> dict[str, Any]:
        """Apply feature, verdict, alert, and checkpoint changes atomically."""
        events = list(events)
        metrics.increment("rules.evaluation_batches")
        buckets, paths = _feature_deltas(events)
        if not buckets:
            return {"processed": False, "affected": set()}
        affected = {ip for ip, _ in buckets}
        received_by_ip = self._received_at_by_ip(events)
        now = now or utcnow()
        failpoint = failpoint or NoopFailpoint()
        failpoint.hit("after_parse")
        processed = self._apply_detection_transaction(
            events, batch_id, dataset_id, source_id, start_offset, end_offset,
            log_key, status, buckets, paths, affected, received_by_ip, now, owner, failpoint,
        )
        if not processed:
            return {"processed": False, "duplicate": True, "affected": set(affected)}
        return {"processed": True, "duplicate": False, "affected": affected}
