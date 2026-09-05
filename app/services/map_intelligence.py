"""Read-only country map intelligence assembled from existing PG state."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from ..core.regions import market_score
from ..db import postgres
from ..db.repositories import RegionRepository


RANGE_HOURS = {"1h": 1, "24h": 24, "7d": 24 * 7}


def _utc_iso(value: Any) -> str | None:
    if value in (None, ""):
        return None
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _number(value: Any, default: float | None = None) -> float | None:
    try:
        return float(value) if value is not None else default
    except (TypeError, ValueError):
        return default


def _score(region: dict[str, Any]) -> float | None:
    value = region.get("market_score")
    if value is None:
        value = market_score(region).get("market_score")
    value = _number(value)
    return round(min(100.0, max(0.0, value)), 2) if value is not None else None


class MapIntelligenceService:
    """Country-level map read model; it has no mutation or enrichment path."""

    def __init__(
        self,
        region_repository: Any | None = None,
        read_threats: Callable[[datetime, datetime], list[dict[str, Any]]] | None = None,
        clock: Callable[[], datetime] | None = None,
        city_opportunities: Callable[[str], list[dict[str, Any]]] | None = None,
        city_state: Callable[[str, datetime, datetime], dict[str, Any]] | None = None,
    ) -> None:
        self._regions = region_repository or RegionRepository()
        self._read_threats = read_threats or _read_country_threats
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._city_opportunities = city_opportunities or _read_city_opportunities
        self._city_state = city_state or _read_city_state

    def world(self, range_name: str = "24h") -> dict[str, Any]:
        if range_name not in RANGE_HOURS:
            raise ValueError(f"unsupported map range: {range_name}")
        generated_at = self._clock()
        if generated_at.tzinfo is None:
            generated_at = generated_at.replace(tzinfo=timezone.utc)
        generated_at = generated_at.astimezone(timezone.utc)
        start = generated_at - timedelta(hours=RANGE_HOURS[range_name])

        opportunity_by_code: dict[str, dict[str, Any]] = {}
        for raw in self._regions.list(limit=1000):
            region = dict(raw or {})
            code = str(region.get("country_code") or "").strip().upper()
            if not code:
                continue
            opportunity_by_code[code] = {
                "score": _score(region),
                "updated_at": _utc_iso(region.get("updated_at")),
                "country_name": region.get("country_name") or code,
            }

        countries: list[dict[str, Any]] = []
        for raw in self._read_threats(start, generated_at):
            threat = dict(raw)
            code = str(threat.get("country_code") or "").strip().upper()
            # No country marker is emitted for unresolved location data.
            if not code:
                continue
            opportunity = opportunity_by_code.get(code, {})
            country_name = opportunity.get("country_name") or threat.get("country_name") or code
            countries.append({
                "country_code": code,
                "country_name": country_name,
                "latitude": _number(threat.get("latitude")),
                "longitude": _number(threat.get("longitude")),
                "opportunity": {
                    "score": opportunity.get("score"),
                    "updated_at": opportunity.get("updated_at"),
                },
                "threat": {
                    "critical_ips": int(threat.get("critical_ips") or 0),
                    "medium_ips": int(threat.get("medium_ips") or 0),
                    "low_ips": int(threat.get("low_ips") or 0),
                    "good_ips": int(threat.get("good_ips") or 0),
                    "unknown_ips": int(threat.get("unknown_ips") or 0),
                    "requests": int(threat.get("requests") or 0),
                    "flagged_ips": int(threat.get("critical_ips") or 0) + int(threat.get("medium_ips") or 0),
                    "last_seen_at": _utc_iso(threat.get("last_seen_at")),
                },
            })

        # Include opportunity-only countries when their existing state has coordinates.
        known = {item["country_code"] for item in countries}
        for code, opportunity in opportunity_by_code.items():
            if code in known:
                continue
            countries.append({
                "country_code": code,
                "country_name": opportunity["country_name"],
                "latitude": None,
                "longitude": None,
                "opportunity": {"score": opportunity["score"], "updated_at": opportunity["updated_at"]},
                "threat": {"critical_ips": 0, "medium_ips": 0, "low_ips": 0, "good_ips": 0, "unknown_ips": 0, "requests": 0,
                            "flagged_ips": 0, "last_seen_at": None},
            })
        countries.sort(key=lambda item: (item["country_code"], item["country_name"]))
        return {"generated_at": _utc_iso(generated_at), "range": range_name, "countries": countries}

    def country(self, country_code: str, range_name: str = "24h") -> dict[str, Any] | None:
        if range_name not in RANGE_HOURS:
            raise ValueError(f"unsupported map range: {range_name}")
        code = str(country_code or "").strip().upper()
        if not code:
            return None
        region = None
        getter = getattr(self._regions, "get", None)
        if callable(getter):
            region = getter(code)
        if not region:
            region = next((item for item in self._regions.list(limit=1000)
                           if str(item.get("country_code") or "").upper() == code), None)
        if not region:
            return None

        generated_at = self._clock()
        if generated_at.tzinfo is None:
            generated_at = generated_at.replace(tzinfo=timezone.utc)
        generated_at = generated_at.astimezone(timezone.utc)
        start = generated_at - timedelta(hours=RANGE_HOURS[range_name])
        state = self._city_state(code, start, generated_at)
        opportunities = _collapse_city_opportunities(self._city_opportunities(code))
        threats = {str(item.get("city_key") or ""): dict(item)
                   for item in state.get("cities", []) if item.get("city_key")}
        cities: list[dict[str, Any]] = []
        for key in sorted(set(opportunities) | set(threats)):
            opportunity = opportunities.get(key)
            threat = threats.get(key, {})
            latitude = _number((opportunity or {}).get("latitude"), _number(threat.get("latitude")))
            longitude = _number((opportunity or {}).get("longitude"), _number(threat.get("longitude")))
            # A city marker requires both a persisted identity and usable coordinates.
            if latitude is None or longitude is None:
                continue
            city_name = (opportunity or {}).get("city_name") or threat.get("city_name") or key
            city_id = (opportunity or {}).get("city_id") or f"{code}:CITY:{key}"
            critical = int(threat.get("critical_ips") or 0)
            medium = int(threat.get("medium_ips") or 0)
            low = int(threat.get("low_ips") or 0)
            good = int(threat.get("good_ips") or 0)
            cities.append({
                "city_id": city_id,
                "city_name": city_name,
                "latitude": latitude,
                "longitude": longitude,
                "opportunity": {
                    "score": opportunity.get("score") if opportunity else None,
                    "raw_score": opportunity.get("raw_score") if opportunity else None,
                    "percentile": opportunity.get("percentile") if opportunity else None,
                    "evidence_coverage": opportunity.get("evidence_coverage") if opportunity else None,
                    "updated_at": _utc_iso(opportunity.get("updated_at")) if opportunity else None,
                },
                "threat": {
                    "critical_ips": critical,
                    "medium_ips": medium,
                    "low_ips": low,
                    "good_ips": good,
                    "flagged_ips": critical + medium,
                    "requests": int(threat.get("requests") or 0),
                    "last_seen_at": _utc_iso(threat.get("last_seen_at")),
                },
            })
        return {
            "generated_at": _utc_iso(generated_at),
            "range": range_name,
            "country": {
                "country_code": code,
                "country_name": region.get("country_name") or code,
                "opportunity_score": _score(region),
            },
            "coverage": state.get("coverage", {}),
            "cities": cities,
        }


def _collapse_city_opportunities(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for raw in rows:
        item = dict(raw)
        key = str(item.get("city_name") or "").strip().casefold()
        if (not key or key in {"unknown", "unresolved", "n/a", "na", "none"}
                or _number(item.get("latitude")) is None or _number(item.get("longitude")) is None):
            continue
        item["score"] = _number(item.get("score"))
        if item["score"] is not None:
            item["score"] = round(min(100.0, max(0.0, item["score"])), 2)
        current = result.get(key)
        if current is None or (item["score"] is not None and
                               (current.get("score") is None or item["score"] > current["score"])):
            result[key] = item
    return result


def _read_country_threats(start: datetime, end: datetime) -> list[dict[str, Any]]:
    """Aggregate only already-resolved PG state; this function never enriches IPs."""
    with postgres.transaction() as conn:
        rows = conn.execute(
            """SELECT p.country_code, MAX(p.country) AS country_name,
                      AVG(p.latitude) FILTER (WHERE p.latitude IS NOT NULL) AS latitude,
                      AVG(p.longitude) FILTER (WHERE p.longitude IS NOT NULL) AS longitude,
                      COUNT(DISTINCT f.ip) FILTER (WHERE COALESCE(cs.label, 'unknown') = 'critical') AS critical_ips,
                      COUNT(DISTINCT f.ip) FILTER (WHERE COALESCE(cs.label, 'unknown') = 'medium') AS medium_ips,
                      COUNT(DISTINCT f.ip) FILTER (WHERE COALESCE(cs.label, 'unknown') = 'low') AS low_ips,
                      COUNT(DISTINCT f.ip) FILTER (WHERE COALESCE(cs.label, 'unknown') = 'good') AS good_ips,
                      COUNT(DISTINCT f.ip) FILTER (WHERE COALESCE(cs.label, 'unknown') = 'unknown') AS unknown_ips,
                      COALESCE(SUM(f.requests), 0) AS requests, MAX(f.last_seen) AS last_seen_at
                 FROM ip_minute_features f
                 JOIN ip_profiles p ON p.ip = f.ip AND NULLIF(BTRIM(p.country_code), '') IS NOT NULL
                 LEFT JOIN ip_classification_state cs ON cs.ip = f.ip
                WHERE f.dataset_id = 'live' AND f.bucket_minute >= %s AND f.bucket_minute <= %s
                GROUP BY p.country_code
                ORDER BY p.country_code""",
            (start, end),
        ).fetchall()
    return [dict(row) for row in rows]


def _read_city_opportunities(country_code: str) -> list[dict[str, Any]]:
    with postgres.transaction() as conn:
        rows = conn.execute("""SELECT o.city_id,a.name AS city_name,a.centroid_lat AS latitude,
                                      a.centroid_lon AS longitude,o.city_raw_score AS raw_score,
                                      o.city_calibrated_score AS score,o.city_percentile AS percentile,
                                      o.evidence_coverage,o.updated_at
                                 FROM market_city_opportunity_summary o
                                 JOIN market_osm_snapshots s ON s.snapshot_id=o.snapshot_id
                                  AND s.country_code=o.country_code AND s.active
                                 JOIN market_areas a ON a.area_id=o.city_id AND a.active
                                WHERE o.country_code=%s
                                ORDER BY a.name,o.city_calibrated_score DESC NULLS LAST,o.city_id""",
                            (country_code.upper(),)).fetchall()
    return [dict(row) for row in rows]


def _read_city_state(country_code: str, start: datetime, end: datetime) -> dict[str, Any]:
    with postgres.transaction() as conn:
        coverage = conn.execute("""WITH active AS (
                    SELECT f.ip,SUM(f.requests) AS requests,
                           NULLIF(BTRIM(p.city),'') IS NOT NULL
                             AND LOWER(BTRIM(p.city)) NOT IN ('unknown','unresolved','n/a','na','none')
                             AND p.latitude IS NOT NULL AND p.longitude IS NOT NULL AS located
                      FROM ip_minute_features f JOIN ip_profiles p ON p.ip=f.ip
                     WHERE f.dataset_id='live' AND p.country_code=%s
                       AND f.bucket_minute >= %s AND f.bucket_minute <= %s
                     GROUP BY f.ip,p.city,p.latitude,p.longitude)
                    SELECT COUNT(*) AS total_ips,
                           COUNT(*) FILTER (WHERE located) AS located_ips,
                           COALESCE(SUM(requests),0) AS total_requests,
                           COALESCE(SUM(requests) FILTER (WHERE located),0) AS located_requests
                      FROM active""", (country_code.upper(), start, end)).fetchone()
        rows = conn.execute("""SELECT LOWER(BTRIM(p.city)) AS city_key,MAX(BTRIM(p.city)) AS city_name,
                                      AVG(p.latitude) AS latitude,AVG(p.longitude) AS longitude,
                                      COUNT(DISTINCT f.ip) FILTER (WHERE COALESCE(cs.label,'unknown')='critical') AS critical_ips,
                                      COUNT(DISTINCT f.ip) FILTER (WHERE COALESCE(cs.label,'unknown')='medium') AS medium_ips,
                                      COUNT(DISTINCT f.ip) FILTER (WHERE COALESCE(cs.label,'unknown')='low') AS low_ips,
                                      COUNT(DISTINCT f.ip) FILTER (WHERE COALESCE(cs.label,'unknown')='good') AS good_ips,
                                      SUM(f.requests) AS requests,MAX(f.last_seen) AS last_seen_at
                                 FROM ip_minute_features f JOIN ip_profiles p ON p.ip=f.ip
                                 LEFT JOIN ip_classification_state cs ON cs.ip=f.ip
                                WHERE f.dataset_id='live' AND p.country_code=%s
                                  AND f.bucket_minute >= %s AND f.bucket_minute <= %s
                                  AND NULLIF(BTRIM(p.city),'') IS NOT NULL
                                  AND LOWER(BTRIM(p.city)) NOT IN ('unknown','unresolved','n/a','na','none')
                                  AND p.latitude IS NOT NULL AND p.longitude IS NOT NULL
                                GROUP BY LOWER(BTRIM(p.city)) ORDER BY LOWER(BTRIM(p.city))""",
                            (country_code.upper(), start, end)).fetchall()
    total = int((coverage or {}).get("total_ips") or 0)
    located = int((coverage or {}).get("located_ips") or 0)
    return {
        "coverage": {
            "located_ips": located,
            "total_ips": total,
            "city_coverage": round(located / total, 4) if total else None,
            "unlocated_ips": total - located,
            "total_requests": int((coverage or {}).get("total_requests") or 0),
            "located_requests": int((coverage or {}).get("located_requests") or 0),
            "unlocated_requests": int((coverage or {}).get("total_requests") or 0) - int((coverage or {}).get("located_requests") or 0),
        },
        "cities": [dict(row) for row in rows],
    }
