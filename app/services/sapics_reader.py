"""Read SAPICS MMDB releases; no runtime GeoIP network calls."""
from __future__ import annotations

import ipaddress
import math
import os
from pathlib import Path

ROOT = Path(os.getenv("SAPICS_DATA_DIR", "data/ip_location"))
_readers = {}
_mtimes = {}

FILES = {
    "user_country": ("country", "user-country.mmdb", "country"),
    "server_country": ("country", "server-country.mmdb", "country"),
    "geolite2_country": ("country", "geolite2-country.mmdb", "country"),
    "dbip_country": ("country", "dbip-country.mmdb", "country"),
    "iptoasn_country": ("country", "iptoasn-country.mmdb", "country"),
    "geolite2_city_v4": ("city", "geolite2-city-ipv4.mmdb", "city"),
    "geolite2_city_v6": ("city", "geolite2-city-ipv6.mmdb", "city"),
    "dbip_city_v4": ("city", "dbip-city-ipv4.mmdb", "city"),
    "dbip_city_v6": ("city", "dbip-city-ipv6.mmdb", "city"),
    "origin_asn": ("asn", "origin-asn.mmdb", "asn"),
    "geolite2_asn": ("asn", "geolite2-asn.mmdb", "asn"),
    "dbip_asn": ("asn", "dbip-asn.mmdb", "asn"),
    "iptoasn_asn": ("asn", "iptoasn-asn.mmdb", "asn"),
}


def _reader(name):
    path = ROOT / FILES[name][0] / FILES[name][1]
    if not path.is_file():
        return None
    mtime = path.stat().st_mtime_ns
    if _mtimes.get(name) != mtime:
        import maxminddb
        old = _readers.get(name)
        if old:
            old.close()
        _readers[name] = maxminddb.open_database(str(path))
        _mtimes[name] = mtime
    return _readers[name]


def _country(name, ip):
    reader = _reader(name)
    if not reader:
        return None
    try:
        record = reader.get(ip) or {}
        return record.get("country_code") or record.get("country", {}).get("iso_code")
    except Exception:
        return None


def _city(name, ip):
    reader = _reader(f"{name}_{'v6' if ipaddress.ip_address(ip).version == 6 else 'v4'}")
    if not reader:
        return None
    try:
        record = reader.get(ip) or {}
        country = record.get("country_code") or record.get("country", {}).get("iso_code")
        if not country:
            return None
        city_value = record.get("city")
        city = city_value if isinstance(city_value, str) else (city_value or {}).get("names", {}).get("en")
        subdivisions = record.get("subdivisions") or []
        state = record.get("state1") or (subdivisions[0].get("names", {}).get("en") if subdivisions else None)
        location = record.get("location") or {}
        latitude = record.get("latitude", location.get("latitude"))
        longitude = record.get("longitude", location.get("longitude"))
        return {"country_code": country, "city": city, "state": state,
                "latitude": latitude, "longitude": longitude,
                "timezone": location.get("time_zone")}
    except Exception:
        return None


def _asn(name, ip):
    reader = _reader(name)
    if not reader:
        return None
    try:
        record = reader.get(ip) or {}
        return {"number": record.get("autonomous_system_number"),
                "organization": record.get("autonomous_system_organization")}
    except Exception:
        return None


def _distance(a, b):
    if not a or not b or a.get("latitude") is None or b.get("latitude") is None:
        return None
    r = 6371.0
    p1, p2 = math.radians(a["latitude"]), math.radians(b["latitude"])
    dp, dl = math.radians(b["latitude"] - a["latitude"]), math.radians(b["longitude"] - a["longitude"])
    h = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(h))


def _known(value) -> bool:
    return value is not None and str(value).strip().lower() not in {"", "unknown", "0", "n/a", "null"}


def _normalize_city_candidate(source: str, value: dict | None) -> dict | None:
    """Normalize one vendor record without mixing fields from other vendors."""
    if not value or not _valid_country(value.get("country_code")):
        return None
    candidate = dict(value)
    candidate["source"] = source
    candidate["city"] = str(candidate.get("city")).strip() if _known(candidate.get("city")) else None
    try:
        latitude = float(candidate["latitude"]) if candidate.get("latitude") is not None else None
        longitude = float(candidate["longitude"]) if candidate.get("longitude") is not None else None
    except (TypeError, ValueError):
        latitude = longitude = None
    if latitude is not None and not -90 <= latitude <= 90:
        latitude = None
    if longitude is not None and not -180 <= longitude <= 180:
        longitude = None
    candidate["latitude"], candidate["longitude"] = latitude, longitude
    candidate["valid"] = True
    candidate["invalid_reason"] = None
    candidate["coordinate_granularity"] = "city" if candidate["city"] and latitude is not None and longitude is not None else "country" if latitude is not None and longitude is not None else "unknown"
    candidate["is_likely_fallback_value"] = candidate["city"] is None and latitude is not None and longitude is not None
    return candidate


def _valid_country(value) -> bool:
    return _known(value) and len(str(value).strip()) == 2 and str(value).strip().isalpha()


def lookup(ip: str) -> dict:
    ipaddress.ip_address(ip)
    countries = {name: _country(name, ip) for name in ("user_country", "server_country", "geolite2_country", "dbip_country", "iptoasn_country")}
    cities = {name: _normalize_city_candidate(name, _city(name, ip)) for name in ("geolite2_city", "dbip_city")}
    asns = {name: _asn(name, ip) for name in ("origin_asn", "geolite2_asn", "dbip_asn", "iptoasn_asn")}
    valid_countries = {name: value for name, value in countries.items() if _valid_country(value)}
    user = valid_countries.get("user_country")
    country_groups = {}
    for source, value in valid_countries.items():
        country_groups.setdefault(str(value).upper(), []).append(source)
    source_priority = ("user_country", "server_country", "geolite2_country", "dbip_country", "iptoasn_country")
    ranked_countries = sorted(country_groups.items(), key=lambda pair: (-len(pair[1]), min(source_priority.index(source) for source in pair[1])))
    country_choice = ranked_countries[0][0] if ranked_countries else None
    city_candidates = {name: value for name, value in cities.items() if value}
    known_city_candidates = {name: value for name, value in city_candidates.items() if _known(value.get("city"))}
    city = known_city_candidates.get("geolite2_city") or known_city_candidates.get("dbip_city")
    city_distance = _distance(cities["geolite2_city"], cities["dbip_city"])
    coordinate_conflict = city_distance is not None and city_distance > 25
    city_conflict = coordinate_conflict or (len({str(value.get("city")).strip().lower() for value in known_city_candidates.values()}) > 1)
    city_severity = "high" if city_distance and city_distance > 100 else "medium" if city_conflict else "none"
    country_conflict = len(ranked_countries) > 1
    total_country_sources = sum(len(sources) for _, sources in ranked_countries)
    winner_count = len(ranked_countries[0][1]) if ranked_countries else 0
    clear_majority = bool(winner_count and winner_count > total_country_sources / 2)
    country_severity = "none" if not country_conflict else "low" if winner_count / total_country_sources >= .75 else "medium" if clear_majority else "high"
    country_status = "unresolved" if not country_choice else "disputed" if country_conflict and not clear_majority else "resolved_with_conflict" if country_conflict else "resolved"
    origin = asns["origin_asn"]
    canonical_city = city if city and not city_conflict else None
    return {"country": {"value": country_choice, "source": "sapics_consensus", "conflict": country_conflict,
                         "status": country_status, "conflict_severity": country_severity,
                         "agreement": {code: len(sources) for code, sources in ranked_countries},
                         "candidates": countries},
            "city": {"value": canonical_city.get("city") if canonical_city else None, "source": canonical_city.get("source") if canonical_city else "none",
                     "state": canonical_city.get("state") if canonical_city else None, "latitude": canonical_city.get("latitude") if canonical_city else None,
                     "longitude": canonical_city.get("longitude") if canonical_city else None, "timezone": canonical_city.get("timezone") if canonical_city else None,
                     "coordinate_granularity": canonical_city.get("coordinate_granularity", "unknown") if canonical_city else "unknown",
                     "conflict": city_conflict, "coordinate_conflict": coordinate_conflict,
                     "status": "disputed" if city_conflict else "resolved" if canonical_city else "unresolved",
                     "conflict_severity": city_severity, "distance_km": round(city_distance, 1) if city_distance else None,
                     "candidates": cities},
            "infrastructure": {"server_country": countries["server_country"], "cross_region": bool(user and countries["server_country"] and user != countries["server_country"])},
            "asn": {"number": origin.get("number") if origin else None, "organization": origin.get("organization") if origin else None,
                    "source": "origin_asn", "candidates": asns}}
