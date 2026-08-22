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


def _candidates(ip: str) -> list[str]:
    address = ipaddress.ip_address(ip)
    return [str(ipaddress.ip_network(value, strict=False)) for value in candidate_networks(address)]


def _resolution(row: Any) -> dict[str, Any]:
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
    radius = 6371.0
    a1, a2 = math.radians(lat1), math.radians(lat2)
    da, dl = math.radians(lat2 - lat1), math.radians(lon2 - lon1)
    value = math.sin(da / 2) ** 2 + math.cos(a1) * math.cos(a2) * math.sin(dl / 2) ** 2
    return 2 * radius * math.asin(math.sqrt(value))


def _resolve_city(candidates, country_code):
    def pick(name):
        return next((c for c in candidates if name in str(c.get("source", "")).lower()
                     and str(c.get("country_code", "")).upper() == country_code
                     and c.get("latitude") is not None and c.get("longitude") is not None), None)
    primary, fallback = pick("maxmind"), pick("dbip")
    if not primary and not fallback:
        return {"city": None, "latitude": None, "longitude": None, "city_source": "none",
                "city_disputed": False, "city_confidence": 0, "city_distance_km": None}
    chosen = primary or fallback
    distance = _haversine(primary["latitude"], primary["longitude"], fallback["latitude"], fallback["longitude"]) if primary and fallback else None
    disputed = distance is not None and distance > float(os.getenv("GEO_CITY_CONFLICT_KM", "50"))
    confidence = int(chosen.get("source_confidence") or 0)
    return {"city": chosen.get("city"), "latitude": chosen.get("latitude"), "longitude": chosen.get("longitude"),
            "city_source": "maxmind" if primary else "dbip", "city_disputed": disputed,
            "city_confidence": max(20, confidence - 25) if disputed else confidence,
            "city_distance_km": round(distance, 1) if distance is not None else None}


def resolve_network_location(ip: str, vendor: dict | None = None, force_refresh: bool = False) -> dict[str, Any]:
    address = ipaddress.ip_address(ip)
    candidates = _candidates(str(address))
    with transaction() as conn:
        cached = conn.execute("SELECT * FROM geo_resolutions WHERE ip=%s AND (expires_at IS NULL OR expires_at>=now())", (str(address),)).fetchone()
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
        groups = {}
        for item in operational: groups.setdefault(str(item.get("country_code") or "").upper(), []).append(item)
        code, items = max(groups.items(), key=lambda pair: sum(int(x.get("source_confidence") or 0) for x in pair[1]))
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
