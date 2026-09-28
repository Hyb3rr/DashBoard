"""Read-only country map intelligence assembled from existing PG state."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from ..core.regions import market_score
from ..config import settings
from ..db import postgres
from ..db.repositories import RegionRepository
from ..core.vietnam_geography import PROVINCES


RANGE_HOURS = {"30m": 0.5, "1h": 1, "6h": 6, "12h": 12, "24h": 24, "3d": 24 * 3, "7d": 24 * 7, "30d": 24 * 30}

# Explicit backend crosswalk: unknown GeoIP localities remain unmapped.
_VN_CITY_TO_GEO_UNIT = {
    "ha noi": "01", "hanoi": "01", "cao bang": "04", "tuyen quang": "08",
    "dien bien": "11", "lai chau": "12", "son la": "14", "lao cai": "15",
    "thai nguyen": "19", "lang son": "20", "quang ninh": "22", "bac ninh": "24",
    "phu tho": "25", "hai phong": "31", "hung yen": "33", "ninh binh": "37",
    "thanh hoa": "38", "nghe an": "40", "ha tinh": "42", "quang tri": "44",
    "hue": "46", "thua thien hue": "46", "da nang": "48", "quang ngai": "51",
    "gia lai": "52", "khanh hoa": "56", "dak lak": "66", "daklak": "66",
    "lam dong": "68", "dong nai": "75", "ho chi minh": "79",
    "ho chi minh city": "79", "sai gon": "79", "saigon": "79", "tay ninh": "80",
    "dong thap": "82", "vinh long": "86", "an giang": "91", "can tho": "92", "ca mau": "96",
}
_VN_NAME_BY_ID = {str(item["code"]): item["name"] for item in PROVINCES}


def _vn_city_key(value: Any) -> str:
    """Normalize a Vietnam locality label for the explicit province crosswalk."""
    import unicodedata
    text = unicodedata.normalize("NFKD", str(value or "")).casefold().replace("đ", "d")
    return "".join(char for char in text if not unicodedata.combining(char) and (char.isalnum() or char == " ")).strip()


def _canonical_market_geo_unit(country_code: str, city_name: Any) -> str | None:
    """Return a canonical market geo-unit only for proven Vietnam localities."""
    if str(country_code or "").upper() != "VN":
        return None
    return _VN_CITY_TO_GEO_UNIT.get(_vn_city_key(city_name))


def _canonical_vn_traffic(state: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Group mapped Vietnam traffic by canonical province and retain unmapped totals."""
    grouped: dict[str, dict[str, Any]] = {}
    unmapped = {"observed_ips": 0, "requests": 0}
    for raw in state.get("cities", []):
        item = dict(raw)
        geo_id = _canonical_market_geo_unit("VN", item.get("city_name") or item.get("city_key"))
        if geo_id is None:
            unmapped["observed_ips"] += int(item.get("observed_ips") or 0)
            unmapped["requests"] += int(item.get("requests") or 0)
            continue
        row = grouped.setdefault(geo_id, {"city_key": geo_id, "city_name": _VN_NAME_BY_ID[geo_id],
            "latitude": None, "longitude": None, "critical_ips": 0, "medium_ips": 0,
            "low_ips": 0, "good_ips": 0, "observed_ips": 0, "requests": 0, "last_seen_at": None})
        for field in ("critical_ips", "medium_ips", "low_ips", "good_ips", "observed_ips", "requests"):
            row[field] += int(item.get(field) or 0)
        if row["latitude"] is None and _number(item.get("latitude")) is not None:
            row["latitude"], row["longitude"] = _number(item.get("latitude")), _number(item.get("longitude"))
        if item.get("last_seen_at") and (row["last_seen_at"] is None or str(item["last_seen_at"]) > str(row["last_seen_at"])):
            row["last_seen_at"] = item["last_seen_at"]
    return list(grouped.values()), unmapped


def _utc_iso(value: Any) -> str | None:
    """Normalize supported timestamps to UTC ISO-8601 strings."""
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
    """Convert a numeric value safely while preserving unavailable values."""
    try:
        return float(value) if value is not None else default
    except (TypeError, ValueError):
        return default


def _score(region: dict[str, Any]) -> float | None:
    """Return the bounded two-decimal market score for a country profile."""
    value = region.get("market_score")
    if value is None:
        value = market_score(region).get("market_score")
    value = _number(value)
    return round(min(100.0, max(0.0, value)), 2) if value is not None else None


def _window(range_name: str, start: datetime | None, end: datetime | None, clock: Callable[[], datetime]) -> tuple[datetime, datetime, str]:
    """Resolve a named or custom map window into an ordered UTC interval."""
    if start is None and end is None:
        if range_name not in RANGE_HOURS:
            raise ValueError(f"unsupported map range: {range_name}")
        end = clock()
        start = end - timedelta(hours=RANGE_HOURS[range_name])
        resolved_range = range_name
    elif start is not None and end is not None:
        resolved_range = "custom"
    else:
        raise ValueError("custom map window requires both start and end")
    if start.tzinfo is None:
        start = start.replace(tzinfo=timezone.utc)
    if end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)
    start = start.astimezone(timezone.utc)
    end = end.astimezone(timezone.utc)
    if end <= start:
        raise ValueError("custom map window must end after it starts")
    return start, end, resolved_range


def _world_opportunity_index(regions: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Index country market context by normalized ISO country code."""
    opportunities = {}
    for raw in regions:
        region = dict(raw or {})
        code = str(region.get("country_code") or "").strip().upper()
        if code:
            opportunities[code] = {
                "score": _score(region),
                "updated_at": _utc_iso(region.get("updated_at")),
                "country_name": region.get("country_name") or code,
            }
    return opportunities


def _country_threat_marker(threat: dict[str, Any], opportunity: dict[str, Any]) -> dict[str, Any]:
    """Build one world-map country marker from persisted threat and market state."""
    code = str(threat.get("country_code") or "").strip().upper()
    return {
        "country_code": code,
        "country_name": opportunity.get("country_name") or threat.get("country_name") or code,
        "latitude": _number(threat.get("latitude")),
        "longitude": _number(threat.get("longitude")),
        "coordinate_status": "unknown",
        "coordinate_granularity": "country",
        "marker_scope": "country_aggregate",
        "opportunity": {"score": opportunity.get("score"), "updated_at": opportunity.get("updated_at")},
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
    }


def _opportunity_only_marker(code: str, opportunity: dict[str, Any]) -> dict[str, Any]:
    """Build a country marker when market context exists without threat traffic."""
    return {
        "country_code": code,
        "country_name": opportunity["country_name"],
        "latitude": None,
        "longitude": None,
        "coordinate_status": "unknown",
        "coordinate_granularity": "country",
        "marker_scope": "country_aggregate",
        "opportunity": {"score": opportunity["score"], "updated_at": opportunity["updated_at"]},
        "threat": {"critical_ips": 0, "medium_ips": 0, "low_ips": 0, "good_ips": 0,
                   "unknown_ips": 0, "requests": 0, "flagged_ips": 0, "last_seen_at": None},
    }


def _country_city_threats(code: str, state: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Select canonical Vietnam or persisted locality traffic for a country."""
    if code == "VN":
        rows, _unmapped = _canonical_vn_traffic(state)
        return {str(item["city_key"]): item for item in rows}
    return {
        str(item.get("city_key") or ""): dict(item)
        for item in state.get("cities", []) if item.get("city_key")
    }


def _city_opportunity_marker(opportunity: dict[str, Any] | None) -> dict[str, Any]:
    """Serialize the available market score fields for a city marker."""
    return {
        "score": opportunity.get("score") if opportunity else None,
        "raw_score": opportunity.get("raw_score") if opportunity else None,
        "percentile": opportunity.get("percentile") if opportunity else None,
        "evidence_coverage": opportunity.get("evidence_coverage") if opportunity else None,
        "updated_at": _utc_iso(opportunity.get("updated_at")) if opportunity else None,
    }


def _city_threat_marker(threat: dict[str, Any]) -> dict[str, Any]:
    """Serialize traffic counts and derive the flagged-IP total for a marker."""
    critical = int(threat.get("critical_ips") or 0)
    medium = int(threat.get("medium_ips") or 0)
    return {
        "critical_ips": critical,
        "medium_ips": medium,
        "low_ips": int(threat.get("low_ips") or 0),
        "good_ips": int(threat.get("good_ips") or 0),
        "observed_ips": int(threat.get("observed_ips") or 0),
        "flagged_ips": critical + medium,
        "requests": int(threat.get("requests") or 0),
        "last_seen_at": _utc_iso(threat.get("last_seen_at")),
    }


def _city_markers(code: str, opportunities: dict[str, dict[str, Any]],
                  threats: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Combine city opportunity and traffic rows into map-ready markers."""
    cities = []
    for key in sorted(set(opportunities) | set(threats)):
        opportunity = opportunities.get(key)
        threat = threats.get(key, {})
        latitude = _number((opportunity or {}).get("latitude"), _number(threat.get("latitude")))
        longitude = _number((opportunity or {}).get("longitude"), _number(threat.get("longitude")))
        if latitude is None or longitude is None:
            continue
        city_name = (opportunity or {}).get("city_name") or threat.get("city_name") or key
        city_id = (opportunity or {}).get("city_id") or (key if code == "VN" else f"{code}:CITY:{key}")
        cities.append({
            "city_id": city_id,
            "city_name": city_name,
            "latitude": latitude,
            "longitude": longitude,
            "coordinate_status": "resolved",
            "coordinate_granularity": "city",
            "opportunity": _city_opportunity_marker(opportunity),
            "threat": _city_threat_marker(threat),
        })
    return cities


def _vietnam_traffic_coverage(state: dict[str, Any], cities: list[dict[str, Any]]) -> dict[str, Any]:
    """Report canonical and residual Vietnam traffic with a conservation check."""
    coverage = dict(state.get("coverage", {}))
    canonical = {
        "observed_ips": sum(int(item["threat"]["observed_ips"]) for item in cities),
        "requests": sum(int(item["threat"]["requests"]) for item in cities),
    }
    unmapped = {
        "observed_ips": max(0, int(coverage.get("total_ips") or 0) - canonical["observed_ips"]),
        "requests": max(0, int(coverage.get("total_requests") or 0) - canonical["requests"]),
    }
    coverage["canonical_traffic"] = canonical
    coverage["unmapped_traffic"] = unmapped
    coverage["traffic_conservation"] = (
        canonical["requests"] + unmapped["requests"] == int(coverage.get("total_requests") or 0)
        and canonical["observed_ips"] + unmapped["observed_ips"] == int(coverage.get("total_ips") or 0)
    )
    return coverage


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
        """Wire read-only repositories and optional deterministic test seams."""
        self._regions = region_repository or RegionRepository()
        self._read_threats = read_threats or _read_country_threats
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._city_opportunities = city_opportunities or _read_city_opportunities
        self._city_state = city_state or _read_city_state

    def world(self, range_name: str = "24h", start: datetime | None = None, end: datetime | None = None) -> dict[str, Any]:
        """Return country-level opportunity and threat markers for one time window."""
        generated_at = self._clock()
        if generated_at.tzinfo is None:
            generated_at = generated_at.replace(tzinfo=timezone.utc)
        generated_at = generated_at.astimezone(timezone.utc)
        start, generated_at, resolved_range = _window(range_name, start, end, lambda: generated_at)

        opportunity_by_code = _world_opportunity_index(self._regions.list(limit=1000))
        countries = []
        for raw in self._read_threats(start, generated_at):
            threat = dict(raw)
            code = str(threat.get("country_code") or "").strip().upper()
            if code:
                countries.append(_country_threat_marker(threat, opportunity_by_code.get(code, {})))

        known = {item["country_code"] for item in countries}
        countries.extend(
            _opportunity_only_marker(code, opportunity)
            for code, opportunity in opportunity_by_code.items() if code not in known
        )
        countries.sort(key=lambda item: (item["country_code"], item["country_name"]))
        return {"generated_at": _utc_iso(generated_at), "range": resolved_range, "countries": countries}

    def country(self, country_code: str, range_name: str = "24h", start: datetime | None = None, end: datetime | None = None) -> dict[str, Any] | None:
        """Return one country's map profile with city traffic and coverage."""
        code = str(country_code or "").strip().upper()
        if not code:
            return None
        region = self._country_region(code)
        if not region:
            return None

        generated_at = self._clock()
        if generated_at.tzinfo is None:
            generated_at = generated_at.replace(tzinfo=timezone.utc)
        generated_at = generated_at.astimezone(timezone.utc)
        start, generated_at, resolved_range = _window(range_name, start, end, lambda: generated_at)
        state = self._city_state(code, start, generated_at)
        opportunities = _collapse_city_opportunities(self._city_opportunities(code))
        if code == "VN":
            opportunities = {}
        threats = _country_city_threats(code, state)
        cities = _city_markers(code, opportunities, threats)
        if code == "VN":
            coverage = _vietnam_traffic_coverage(state, cities)
        else:
            coverage = dict(state.get("coverage", {}))
        return {
            "generated_at": _utc_iso(generated_at),
            "range": resolved_range,
            "country": {
                "country_code": code,
                "country_name": region.get("country_name") or code,
                "opportunity_score": _score(region),
            },
            "coverage": coverage,
            "cities": cities,
        }

    def _country_region(self, code: str) -> dict[str, Any] | None:
        """Read a country profile by direct lookup with a bounded list fallback."""
        getter = getattr(self._regions, "get", None)
        region = getter(code) if callable(getter) else None
        if region:
            return region
        return next((item for item in self._regions.list(limit=1000)
                     if str(item.get("country_code") or "").upper() == code), None)


def _collapse_city_opportunities(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Keep one usable opportunity record per city label."""
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
                      COUNT(DISTINCT p.ip) FILTER (WHERE f.ip IS NOT NULL AND COALESCE(cs.label, 'unknown') = 'critical') AS critical_ips,
                      COUNT(DISTINCT p.ip) FILTER (WHERE f.ip IS NOT NULL AND COALESCE(cs.label, 'unknown') = 'medium') AS medium_ips,
                      COUNT(DISTINCT p.ip) FILTER (WHERE f.ip IS NOT NULL AND COALESCE(cs.label, 'unknown') = 'low') AS low_ips,
                      COUNT(DISTINCT p.ip) FILTER (WHERE COALESCE(cs.label, 'unknown') = 'good' AND f.ip IS NOT NULL) AS good_ips,
                      COUNT(DISTINCT p.ip) FILTER (WHERE COALESCE(cs.label, 'unknown') = 'unknown' AND f.ip IS NOT NULL) AS unknown_ips,
                      COALESCE(SUM(f.requests), 0) AS requests, MAX(f.last_seen) AS last_seen_at
                 FROM ip_profiles p
                 LEFT JOIN (
                    SELECT ip, SUM(requests) AS requests, MAX(last_seen) AS last_seen
                      FROM ip_minute_features
                     WHERE dataset_id = %s AND bucket_minute >= %s AND bucket_minute <= %s
                     GROUP BY ip
                 ) f ON f.ip = p.ip
                 LEFT JOIN ip_classification_state cs ON cs.ip = p.ip
                WHERE NULLIF(BTRIM(p.country_code), '') IS NOT NULL
                GROUP BY p.country_code
                HAVING COALESCE(SUM(f.requests), 0) > 0
                ORDER BY p.country_code""",
            (settings.DATASET_LIVE_ID, start, end),
        ).fetchall()
    return [dict(row) for row in rows]


def _read_city_opportunities(country_code: str) -> list[dict[str, Any]]:
    """Read active city opportunity rows for one country."""
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
    """Read city threat aggregates and location coverage for a map window."""
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
                                      COUNT(DISTINCT f.ip) AS observed_ips,
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
