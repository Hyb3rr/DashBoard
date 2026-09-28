"""PostgreSQL read models for IP inventory, summaries, and change feeds."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from .postgres import transaction


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
    def _where(q: str | None, privacy: str | None, classification: str | None, disposition: str | None, intel_tag: str | None = None) -> tuple[str, list[Any]]:
        """Build safe, parameterized filters for IP inventory queries."""
        clauses = ["TRUE"]
        args: list[Any] = []
        if q:
            term = f"%{q.strip()}%"
            clauses.append("(i.ip::text ILIKE %s OR COALESCE(p.country,gr_country,'') ILIKE %s OR COALESCE(p.country_code,gr_country_code,'') ILIKE %s OR COALESCE(p.asn,gr_asn,'') ILIKE %s OR COALESCE(p.organization,gr_organization,'') ILIKE %s)")
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
        abuse_1d = "COALESCE(p.provider_status, '{}'::jsonb) ? 'firehol:abuseipdb_1d'"
        abuse_30d = "COALESCE(p.provider_status, '{}'::jsonb) ? 'firehol:abuseipdb_30d'"
        if intel_tag == "intel:abuse_recent":
            clauses.append(f"({abuse_1d} AND NOT {abuse_30d})")
        elif intel_tag == "intel:abuse_historical":
            clauses.append(f"({abuse_30d} AND NOT {abuse_1d})")
        elif intel_tag == "intel:abuse_persistent":
            clauses.append(f"({abuse_1d} AND {abuse_30d})")
        elif intel_tag == "intel:any_abuse":
            clauses.append(f"({abuse_1d} OR {abuse_30d})")
        return " AND ".join(clauses), args

    def page(self, page: int, page_size: int, sort: str, direction: str, q: str | None = None,
             privacy: str | None = None, classification: str | None = None, disposition: str | None = None,
             intel_tag: str | None = None) -> dict[str, Any]:
        """Return a filtered and sorted page of compact IP inventory rows."""
        where, args = self._where(q, privacy, classification, disposition, intel_tag)
        order = self._sorts.get(sort, self._sorts["threat_signal_score"])
        order_direction = "ASC" if direction.lower() == "asc" else "DESC"
        with transaction() as conn:
            total = conn.execute(
                f"""WITH identities AS (SELECT ip FROM ip_observations_state UNION SELECT ip FROM ip_profiles)
                    SELECT COUNT(*) AS n FROM identities i
                    LEFT JOIN ip_observations_state o ON o.ip=i.ip
                    LEFT JOIN ip_profiles p ON p.ip=i.ip
                    LEFT JOIN LATERAL (SELECT country AS gr_country, country_code AS gr_country_code, city AS gr_city, asn AS gr_asn, organization AS gr_organization, network_type AS gr_network_type, confidence AS gr_confidence, disputed AS gr_disputed, location_scope AS gr_location_scope FROM geo_resolutions WHERE ip=i.ip LIMIT 1) gr ON TRUE
                    LEFT JOIN ip_classification_state cs ON cs.ip=i.ip
                    LEFT JOIN ip_dispositions d ON d.ip=i.ip WHERE {where}""", args,
            ).fetchone()["n"]
            rows = conn.execute(
                f"""WITH identities AS (SELECT ip FROM ip_observations_state UNION SELECT ip FROM ip_profiles)
                    SELECT host(i.ip) AS identity_ip, p.*, o.payload AS observation_payload,
                           gr.gr_country, gr.gr_country_code, gr.gr_city, gr.gr_asn, gr.gr_organization,
                           gr.gr_network_type, gr.gr_confidence, gr.gr_disputed, gr.gr_location_scope,
                           cs.label, cs.score AS classification_score, cs.confidence AS classification_confidence,
                           d.state AS disposition
                      FROM identities i
                      LEFT JOIN ip_observations_state o ON o.ip=i.ip
                      LEFT JOIN ip_profiles p ON p.ip=i.ip
                      LEFT JOIN LATERAL (SELECT country AS gr_country, country_code AS gr_country_code, city AS gr_city, asn AS gr_asn, organization AS gr_organization, network_type AS gr_network_type, confidence AS gr_confidence, disputed AS gr_disputed, location_scope AS gr_location_scope FROM geo_resolutions WHERE ip=i.ip LIMIT 1) gr ON TRUE
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
        """Summarize IP inventory totals and current classification counts."""
        with transaction() as conn:
            row = conn.execute("""WITH identities AS (SELECT ip FROM ip_observations_state UNION SELECT ip FROM ip_profiles)
                SELECT COUNT(*) total,
                  COUNT(*) FILTER (WHERE COALESCE(cs.label,'unknown')='critical') critical,
                  COUNT(*) FILTER (WHERE COALESCE(cs.label,'unknown')='medium') medium,
                  COUNT(*) FILTER (WHERE COALESCE(cs.label,'unknown')='low') low,
                  COUNT(*) FILTER (WHERE COALESCE(cs.label,'unknown')='good') good,
                  COUNT(*) FILTER (WHERE COALESCE(cs.label,'unknown')='unknown') unknown,
                  COUNT(*) FILTER (WHERE COALESCE(p.is_tor,FALSE) OR COALESCE(p.is_vpn,FALSE) OR COALESCE(p.is_proxy,FALSE)) privacy
                FROM identities i LEFT JOIN ip_classification_state cs ON cs.ip=i.ip LEFT JOIN ip_profiles p ON p.ip=i.ip""").fetchone()
            priority = conn.execute("""SELECT host(i.ip) AS ip FROM ip_classification_state cs
                JOIN (SELECT ip FROM ip_observations_state UNION SELECT ip FROM ip_profiles) i ON i.ip=cs.ip
                LEFT JOIN ip_dispositions d ON d.ip=cs.ip
                WHERE cs.label IN ('critical','medium') AND COALESCE(d.state, 'new') != 'resolved'
                ORDER BY cs.score DESC, i.ip ASC LIMIT 5""").fetchall()
        return {"total_ips": int(row["total"] or 0), "classification": {key: int(row[key] or 0) for key in ("critical", "medium", "low", "good", "unknown")}, "privacy": {"total": int(row["privacy"] or 0)}, "priority_ips": [str(item["ip"]) for item in priority]}

    def summary_window(self, start: datetime, end: datetime, dataset_id: str = "live") -> dict[str, Any]:
        """Count classified identities that had traffic in one dashboard window."""
        with transaction() as conn:
            row = conn.execute(
                """SELECT COUNT(DISTINCT f.ip) AS total,
                          COUNT(DISTINCT f.ip) FILTER (WHERE COALESCE(cs.label,'unknown')='critical') AS critical,
                          COUNT(DISTINCT f.ip) FILTER (WHERE COALESCE(cs.label,'unknown')='medium') AS medium,
                          COUNT(DISTINCT f.ip) FILTER (WHERE COALESCE(cs.label,'unknown')='low') AS low,
                          COUNT(DISTINCT f.ip) FILTER (WHERE COALESCE(cs.label,'unknown')='good') AS good,
                          COUNT(DISTINCT f.ip) FILTER (WHERE COALESCE(cs.label,'unknown')='unknown') AS unknown
                     FROM ip_minute_features f
                     LEFT JOIN ip_classification_state cs ON cs.ip=f.ip
                    WHERE f.dataset_id=%s AND f.bucket_minute >= %s AND f.bucket_minute <= %s""",
                (dataset_id, start, end),
            ).fetchone()
            priority = conn.execute("""SELECT host(i.ip) AS ip FROM ip_classification_state cs
                JOIN (SELECT ip FROM ip_observations_state UNION SELECT ip FROM ip_profiles) i ON i.ip=cs.ip
                LEFT JOIN ip_dispositions d ON d.ip=cs.ip
                WHERE cs.label IN ('critical','medium') AND COALESCE(d.state, 'new') != 'resolved'
                ORDER BY cs.score DESC, i.ip ASC LIMIT 5""").fetchall()
        return {
            "total_ips": int(row["total"] or 0),
            "classification": {key: int(row[key] or 0) for key in ("critical", "medium", "low", "good", "unknown")},
            "privacy": {"total": 0},
            "priority_ips": [str(item["ip"]) for item in priority],
        }

    def classification_summary_for_ips(self, ips: list[str]) -> dict[str, Any]:
        """Count current classifications for the exact IP cohort returned by traffic analytics."""
        keys = ("critical", "medium", "low", "good", "unknown")
        values = list(dict.fromkeys(str(ip) for ip in ips))
        if not values:
            return {"total_ips": 0, "classification": {key: 0 for key in keys}}
        with transaction() as conn:
            row = conn.execute(
                """WITH cohort AS (
                       SELECT DISTINCT ip FROM unnest(%s::inet[]) AS ips(ip)
                   )
                   SELECT COUNT(*) AS total,
                          COUNT(*) FILTER (WHERE COALESCE(cs.label,'unknown')='critical') AS critical,
                          COUNT(*) FILTER (WHERE COALESCE(cs.label,'unknown')='medium') AS medium,
                          COUNT(*) FILTER (WHERE COALESCE(cs.label,'unknown')='low') AS low,
                          COUNT(*) FILTER (WHERE COALESCE(cs.label,'unknown')='good') AS good,
                          COUNT(*) FILTER (WHERE COALESCE(cs.label,'unknown')='unknown') AS unknown
                     FROM cohort c
                     LEFT JOIN ip_classification_state cs ON cs.ip=c.ip""",
                (values,),
            ).fetchone()
        return {
            "total_ips": int(row["total"] or 0),
            "classification": {key: int(row[key] or 0) for key in keys},
        }

    def risk_traffic_series(self, start: datetime, end: datetime, bucket_seconds: int, dataset_id: str = "live",
                            filter_type: str | None = None, filter_value: str | None = None,
                            exclude: bool = False) -> list[dict[str, Any]]:
        """Aggregate risk request volume using the same filter as the traffic series."""
        if filter_type == "path":
            return []
        bucket_seconds = max(60, int(bucket_seconds))
        conditions = ["f.dataset_id=%s", "f.bucket_minute >= %s", "f.bucket_minute <= %s"]
        args: list[Any] = [dataset_id, start, end]
        if filter_type == "ip" and filter_value:
            conditions.append("f.ip != %s::inet" if exclude else "f.ip = %s::inet")
            args.append(filter_value)
        elif filter_type == "country" and filter_value:
            conditions.append("COALESCE(p.country_code, '') != %s" if exclude else "p.country_code = %s")
            args.append(str(filter_value).upper())
        elif filter_type == "classification" and filter_value:
            conditions.append("COALESCE(cs.label, 'unknown') != %s" if exclude else "COALESCE(cs.label, 'unknown') = %s")
            args.append(str(filter_value))
        with transaction() as conn:
            rows = conn.execute(
                f"""SELECT date_bin(%s::interval, f.bucket_minute, TIMESTAMPTZ '1970-01-01 00:00:00+00') AS timestamp,
                          COALESCE(SUM(f.requests) FILTER (WHERE COALESCE(cs.label,'unknown')='low'),0) AS low_requests,
                          COALESCE(SUM(f.requests) FILTER (WHERE COALESCE(cs.label,'unknown')='medium'),0) AS medium_requests,
                          COALESCE(SUM(f.requests) FILTER (WHERE COALESCE(cs.label,'unknown')='critical'),0) AS critical_requests
                     FROM ip_minute_features f
                     LEFT JOIN ip_classification_state cs ON cs.ip=f.ip
                     LEFT JOIN ip_profiles p ON p.ip=f.ip
                    WHERE {' AND '.join(conditions)}
                    GROUP BY timestamp ORDER BY timestamp""",
                (f"{bucket_seconds} seconds", *args),
            ).fetchall()
        return [
            {
                "timestamp": row["timestamp"].isoformat() if hasattr(row["timestamp"], "isoformat") else str(row["timestamp"]),
                "low_requests": int(row["low_requests"] or 0),
                "medium_requests": int(row["medium_requests"] or 0),
                "critical_requests": int(row["critical_requests"] or 0),
            }
            for row in rows
        ]

    def get(self, ip: str) -> dict[str, Any] | None:
        """Fetch one combined profile, observation, verdict, and disposition."""
        rows = self.get_many([ip])
        return rows[0] if rows else None

    def get_many(self, ips: Iterable[str]) -> list[dict[str, Any]]:
        """Fetch combined current-state rows for a batch of IPs."""
        values = tuple(dict.fromkeys(str(ip) for ip in ips))
        if not values:
            return []
        with transaction() as conn:
            rows = conn.execute("""SELECT host(i.ip) AS identity_ip,p.*,o.payload AS observation_payload,
                gr.country AS geo_country, gr.country_code AS geo_country_code, gr.city AS geo_city,
                gr.asn AS geo_asn, gr.organization AS geo_organization, gr.network_type AS geo_network_type,
                gr.confidence AS geo_confidence, gr.disputed AS geo_disputed, gr.location_scope AS geo_location_scope,
                cs.label,cs.score AS classification_score,cs.confidence AS classification_confidence,
                d.state AS disposition, d.suggested_state, d.assigned_to, d.note, d.updated_at AS disposition_updated_at, d.history AS disposition_history
                FROM (SELECT ip FROM ip_observations_state UNION SELECT ip FROM ip_profiles) i
                LEFT JOIN ip_profiles p ON p.ip=i.ip LEFT JOIN ip_observations_state o ON o.ip=i.ip
                LEFT JOIN geo_resolutions gr ON gr.ip=i.ip
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
        """Read durable IP change events after a cursor and return its high-water mark."""
        with transaction() as conn:
            current = int(conn.execute("SELECT COALESCE(MAX(seq),0) AS n FROM ip_change_log").fetchone()["n"] or 0)
            oldest = int(conn.execute("SELECT COALESCE(MIN(seq),0) AS n FROM ip_change_log").fetchone()["n"] or 0)
            if after and oldest and after < oldest - 1:
                return {"current": current, "reset_required": True, "rows": []}
            rows = conn.execute("SELECT seq,host(ip) AS ip,reason,old_label,new_label,old_score,new_score,changed_at FROM ip_change_log WHERE seq>%s ORDER BY seq LIMIT %s", (after, limit + 1)).fetchall()
        return {"current": current, "reset_required": False, "rows": [dict(row) for row in rows[:limit]], "has_more": len(rows) > limit}
