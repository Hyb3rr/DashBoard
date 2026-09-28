"""PostgreSQL-only live intelligence lookups.

This module is deliberately read-only. Feed providers may still use the
legacy updater during migration, but live enrichment never opens SQLite.
"""

from __future__ import annotations

import ipaddress
import json
import math
import os
from typing import Any

from .postgres import transaction
from ..core.net_utils import candidate_networks

GEO_RESOLUTION_RULESET = "geo-v5"


def _candidates(ip: str) -> list[str]:
    """Return canonical candidate CIDRs from most-specific IP prefixes."""
    address = ipaddress.ip_address(ip)
    return [str(ipaddress.ip_network(value, strict=False)) for value in candidate_networks(address)]


def _resolution(row: Any) -> dict[str, Any]:
    """Decode cached resolution fields into the public lookup representation."""
    result = dict(row)
    for key in ("source_ids", "evidence"):
        value = result.get(key)
        if isinstance(value, str):
            try:
                result[key] = json.loads(value)
            except json.JSONDecodeError:
                result[key] = [] if key == "source_ids" else {}
    result["disputed"] = bool(result.get("disputed"))
    result["sources"] = result.get("source_ids") or []
    result["scope"] = result.get("location_scope") or "unknown"
    result["confidence_breakdown"] = (result.get("evidence") or {}).get("confidence_breakdown", {})
    return result


def _haversine(lat1, lon1, lat2, lon2):
    """Calculate great-circle distance between two latitude/longitude pairs."""
    radius = 6371.0
    a1, a2 = math.radians(lat1), math.radians(lat2)
    da, dl = math.radians(lat2 - lat1), math.radians(lon2 - lon1)
    value = math.sin(da / 2) ** 2 + math.cos(a1) * math.cos(a2) * math.sin(dl / 2) ** 2
    return 2 * radius * math.asin(math.sqrt(value))


def _known_city(value: Any) -> bool:
    """Return whether a provider value represents a usable city name."""
    return value is not None and str(value).strip().lower() not in {"", "unknown", "0", "n/a", "null"}


def _source_location(candidates: list[dict], source: str, country_code: str, *, require_city: bool) -> dict | None:
    """Select one country's matching provider record with optional city evidence."""
    return next((candidate for candidate in candidates
                 if source in str(candidate.get("source", "")).lower()
                 and str(candidate.get("country_code", "")).upper() == country_code
                 and (not require_city or _known_city(candidate.get("city")))
                 and candidate.get("latitude") is not None and candidate.get("longitude") is not None), None)


def _unresolved_city() -> dict[str, Any]:
    """Return the stable empty result when neither provider has city coordinates."""
    return {"city": None, "latitude": None, "longitude": None, "city_source": "none",
            "city_disputed": False, "coordinate_conflict": False, "city_status": "unresolved",
            "city_confidence": 0, "city_distance_km": None, "coordinate_granularity": "unknown"}


def _city_conflicts(primary: dict | None, fallback: dict | None, distance: float | None) -> tuple[bool, bool | None]:
    """Evaluate coordinate and provider-name disagreement for a city candidate pair."""
    coordinate_conflict = distance is not None and distance > float(os.getenv("GEO_CITY_CONFLICT_KM", "50"))
    name_conflict = (
        str(primary.get("city")).strip().lower() != str(fallback.get("city")).strip().lower()
        if primary and fallback else None
    )
    return coordinate_conflict, coordinate_conflict or name_conflict


def _city_resolution_result(
    primary: dict | None,
    fallback: dict | None,
    disputed: bool,
    coordinate_conflict: bool,
    distance: float | None,
) -> dict[str, Any]:
    """Serialize the selected city and conflict state into the stable response schema."""
    chosen = None if disputed else primary or fallback
    confidence = int(chosen.get("source_confidence") or 0) if chosen else 0
    if disputed:
        status = "disputed"
        confidence = max(20, confidence - 25)
    elif chosen:
        status = "resolved"
    else:
        status = "unresolved"
    source = "maxmind" if chosen is primary else "dbip" if chosen else "none"
    location = chosen or {}
    return {
        "city": location.get("city"),
        "latitude": location.get("latitude"),
        "longitude": location.get("longitude"),
        "city_source": source,
        "city_disputed": disputed,
        "coordinate_conflict": coordinate_conflict,
        "city_status": status,
        "city_confidence": confidence,
        "city_distance_km": round(distance, 1) if distance is not None else None,
        "coordinate_granularity": "city" if chosen else "unknown",
    }


def _resolve_city(candidates, country_code):
    """Resolve city and coordinates with provider precedence and conflict signals."""
    primary = _source_location(candidates, "maxmind", country_code, require_city=True)
    fallback = _source_location(candidates, "dbip", country_code, require_city=True)
    primary_coordinates = _source_location(candidates, "maxmind", country_code, require_city=False)
    fallback_coordinates = _source_location(candidates, "dbip", country_code, require_city=False)
    if not any((primary, fallback, primary_coordinates, fallback_coordinates)):
        return _unresolved_city()
    distance = None
    if primary_coordinates and fallback_coordinates:
        distance = _haversine(
            primary_coordinates["latitude"], primary_coordinates["longitude"],
            fallback_coordinates["latitude"], fallback_coordinates["longitude"],
        )
    coordinate_conflict, disputed = _city_conflicts(primary, fallback, distance)
    return _city_resolution_result(primary, fallback, disputed, coordinate_conflict, distance)


def _country_group(operational: list[dict]) -> tuple[str, list[dict]]:
    """Choose the strongest country cohort with deterministic source ordering."""
    groups = {}
    for item in operational:
        groups.setdefault(str(item.get("country_code") or "").upper(), []).append(item)
    code, items = min(
        groups.items(),
        key=lambda pair: (-sum(int(x.get("source_confidence") or 0) for x in pair[1]), pair[0]),
    )
    return code, sorted(items, key=lambda item: str(item.get("source") or ""))


def resolve_network_location(ip: str, vendor: dict | None = None, force_refresh: bool = False) -> dict[str, Any]:
    """Resolve operational geography and network context from PostgreSQL."""
    address = ipaddress.ip_address(ip)
    candidates = _candidates(str(address))
    with transaction() as conn:
        cached = conn.execute("SELECT * FROM geo_resolutions WHERE ip=%s AND ruleset_version=%s AND (expires_at IS NULL OR expires_at>=now())", (str(address), GEO_RESOLUTION_RULESET)).fetchone()
        if cached and not force_refresh:
            return _resolution(cached)
        prefixes = conn.execute("SELECT * FROM geo_prefixes WHERE active=TRUE AND network=ANY(%s::cidr[])", (candidates,)).fetchall()
        prefixes = sorted(prefixes, key=lambda row: row["network"].prefixlen if hasattr(row["network"], "prefixlen") else len(str(row["network"])), reverse=True)
        best = dict(prefixes[0]) if prefixes else {}
        operational = []
        registration = None
        if best.get("registration_country"):
            registration = {"country_code": best["registration_country"], "source": best.get("source")}
        if best:
            observations = conn.execute("SELECT * FROM geo_location_observations WHERE network=%s", (best["network"],)).fetchall()
            operational.extend(dict(row) for row in observations)
    if not operational and registration:
        return {"network": str(best.get("network")) if best else None, "asn": best.get("asn"), "organization": best.get("organization"), "network_type": best.get("network_type"), "country_code": None, "city": None, "latitude": None, "longitude": None, "confidence": 0, "disputed": False, "scope": "unknown", "sources": [], "registration": registration, "confidence_breakdown": {"method": "no_operational_evidence", "final_score": 0}}
    if not operational:
        return {"network": str(best.get("network")) if best else None, "asn": best.get("asn"), "organization": best.get("organization"), "network_type": best.get("network_type"), "country_code": None, "city": None, "latitude": None, "longitude": None, "confidence": 0, "disputed": False, "scope": "unknown", "sources": [], "registration": registration, "confidence_breakdown": {"method": "no_operational_evidence", "final_score": 0}}
    preferred = next((x for x in operational if "maxmind" in str(x.get("source", "")).lower()), None)
    preferred = preferred or next((x for x in operational if "dbip" in str(x.get("source", "")).lower()), None)
    if preferred:
        code, items = str(preferred.get("country_code")).upper(), [preferred]
    else:
        code, items = _country_group(operational)
    confidence = int(items[0].get("source_confidence") or 0)
    city = _resolve_city(operational, code)
    return {
        "network": str(best.get("network")) if best else None, "asn": best.get("asn"),
        "organization": best.get("organization"), "network_type": best.get("network_type"),
        "country": items[0].get("country"), "country_code": code, "confidence": confidence,
        **city, "disputed": False, "scope": items[0].get("location_scope") or "network",
        "sources": [item.get("source") for item in items if item.get("source")], "registration": registration,
        "confidence_breakdown": {"method": "weighted_consensus", "final_score": confidence, "sources": items},
    }


def local_intelligence(ip: str) -> tuple[dict, dict, dict, list[str]]:
    """Collect active local network signals and attach the resolved location."""
    address = ipaddress.ip_address(ip)
    candidates = _candidates(str(address))
    result: dict[str, Any] = {}
    providers: dict[str, Any] = {}
    fields: dict[str, str] = {}
    errors: list[str] = []
    with transaction() as conn:
        privacy = conn.execute("SELECT * FROM privacy_networks WHERE active=TRUE AND network=ANY(%s::cidr[])", (candidates,)).fetchall()
        threats = conn.execute("SELECT * FROM threat_indicators WHERE active=TRUE AND network=ANY(%s::cidr[])", (candidates,)).fetchall()
    for row in privacy:
        kind = row["kind"]
        field = "is_vpn" if kind == "vpn" else "is_proxy" if kind == "proxy" else "is_hosting"
        result[field] = True
        fields[field] = str(row["source"])
        providers[str(row["source"])] = {"status": "active", "kind": kind}
        if kind == "proxy" and row.get("proxy_type"):
            result["proxy_type"] = row["proxy_type"]
    for row in threats:
        providers[str(row["source"])] = {"status": "active", "category": row["category"]}
        if row["source"] in {"firehol:firehol_proxies", "firehol:firehol_anonymous"}:
            result["is_proxy"] = True
            fields["is_proxy"] = str(row["source"])
    if threats:
        result["threat_indicators"] = [dict(row) for row in threats]
    resolution = resolve_network_location(str(address))
    if resolution.get("country_code"):
        result["network_location"] = resolution
        for key in ("asn", "organization", "network_type", "country", "country_code", "latitude", "longitude", "city"):
            if resolution.get(key) is not None:
                result[key] = resolution[key]
        providers["geo_resolution"] = {"status": "active"}
    return result, providers, fields, errors
