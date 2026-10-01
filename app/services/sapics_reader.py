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
    """Return a cached MMDB reader, reopening it when its file changes."""
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
    """Read a country claim from one MMDB source without propagating lookup errors."""
    reader = _reader(name)
    if not reader:
        return None
    try:
        record = reader.get(ip) or {}
        return record.get("country_code") or record.get("country", {}).get("iso_code")
    except Exception:
        return None


def _city(name, ip):
    """Read city, region, and coordinate evidence from the matching IP family database."""
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
    """Read autonomous-system identity from one MMDB source."""
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
    """Calculate great-circle distance between two GeoIP coordinate records."""
    if not a or not b or a.get("latitude") is None or b.get("latitude") is None:
        return None
    r = 6371.0
    p1, p2 = math.radians(a["latitude"]), math.radians(b["latitude"])
    dp, dl = math.radians(b["latitude"] - a["latitude"]), math.radians(b["longitude"] - a["longitude"])
    h = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(h))


def _known(value) -> bool:
    """Reject empty and common placeholder values as usable GeoIP evidence."""
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
    """Check that a country claim is a two-letter alphabetic code."""
    return _known(value) and len(str(value).strip()) == 2 and str(value).strip().isalpha()


def _vn_parent_key(value) -> str | None:
    """Normalize a provider's Vietnam province/region label for comparison."""
    import re
    import unicodedata

    text = unicodedata.normalize("NFKD", str(value or "")).casefold().replace("đ", "d")
    text = "".join(char for char in text if not unicodedata.combining(char))
    text = re.sub(r"\([^)]*\)", " ", text)
    words = [word for word in re.sub(r"[^a-z0-9]+", " ", text).split()
             if word not in {"city", "province", "municipality", "hcmc", "hcm"}]
    return " ".join(words) or None


def _country_consensus(candidates: dict[str, str | None]) -> dict:
    """Rank country claims by agreement and source priority, preserving conflict metadata."""
    valid = {name: value for name, value in candidates.items() if _valid_country(value)}
    groups: dict[str, list[str]] = {}
    for source, value in valid.items():
        groups.setdefault(str(value).upper(), []).append(source)

    priority = ("user_country", "server_country", "geolite2_country", "dbip_country", "iptoasn_country")
    ranked = sorted(
        groups.items(),
        key=lambda pair: (-len(pair[1]), min(priority.index(source) for source in pair[1])),
    )
    total = sum(len(sources) for _, sources in ranked)
    winner_count = len(ranked[0][1]) if ranked else 0
    conflict = len(ranked) > 1
    majority = bool(winner_count and winner_count > total / 2)
    severity = "none" if not conflict else "low" if winner_count / total >= .75 else "medium" if majority else "high"
    status = "unresolved" if not ranked else "disputed" if conflict and not majority else "resolved_with_conflict" if conflict else "resolved"
    return {
        "value": ranked[0][0] if ranked else None,
        "source": "sapics_consensus",
        "conflict": conflict,
        "status": status,
        "conflict_severity": severity,
        "agreement": {code: len(sources) for code, sources in ranked},
        "candidates": candidates,
        "user_country": valid.get("user_country"),
    }


def _city_consensus(candidates: dict[str, dict | None]) -> dict:
    """Select trusted city evidence and summarize vendor name and coordinate conflicts."""
    available = {name: value for name, value in candidates.items() if value}
    known = {name: value for name, value in available.items() if _known(value.get("city"))}
    city = known.get("geolite2_city") or known.get("dbip_city")
    distance = _distance(candidates["geolite2_city"], candidates["dbip_city"])
    coordinate_conflict = bool(distance is not None and distance > 25)
    names_conflict = len({str(value["city"]).strip().lower() for value in known.values()}) > 1
    parent_keys = {
        _vn_parent_key(value.get("state"))
        for value in known.values()
        if str(value.get("country_code") or "").upper() == "VN" and value.get("state")
    }
    same_vietnam_parent = (
        len(known) > 1
        and len(parent_keys) == 1
        and None not in parent_keys
        and all(str(value.get("country_code") or "").upper() == "VN" for value in known.values())
    )
    # GeoLite may report a province/city while DB-IP reports a district.
    # If both agree on the parent region and coordinates, normalize the city
    # label used downstream while retaining the provider's raw value.
    if same_vietnam_parent and not coordinate_conflict and city:
        for value in known.values():
            if str(value.get("city") or "").strip().casefold() != str(city.get("city") or "").strip().casefold():
                value["raw_city"] = value.get("city")
                value["city"] = city.get("city")
                value["canonicalized_to_shared_parent"] = True
    names_conflict = names_conflict and not same_vietnam_parent
    conflict = coordinate_conflict or names_conflict
    severity = "high" if distance is not None and distance > 100 else "medium" if conflict else "none"
    selected = city if city and not conflict else {}
    status = "disputed" if conflict else "resolved" if selected else "unresolved"
    return {
        "value": selected.get("city"),
        "source": selected.get("source", "none"),
        "state": selected.get("state"),
        "latitude": selected.get("latitude"),
        "longitude": selected.get("longitude"),
        "timezone": selected.get("timezone"),
        "coordinate_granularity": selected.get("coordinate_granularity", "unknown"),
        "conflict": conflict,
        "coordinate_conflict": coordinate_conflict,
        "same_vietnam_parent": same_vietnam_parent,
        "status": status,
        "conflict_severity": severity,
        "distance_km": round(distance, 1) if distance else None,
        "candidates": candidates,
    }


def lookup(ip: str) -> dict:
    """Collect country, city, and ASN candidates and report their conflicts."""
    ipaddress.ip_address(ip)
    countries = {name: _country(name, ip) for name in ("user_country", "server_country", "geolite2_country", "dbip_country", "iptoasn_country")}
    cities = {name: _normalize_city_candidate(name, _city(name, ip)) for name in ("geolite2_city", "dbip_city")}
    asns = {name: _asn(name, ip) for name in ("origin_asn", "geolite2_asn", "dbip_asn", "iptoasn_asn")}
    country = _country_consensus(countries)
    city = _city_consensus(cities)
    origin = asns["origin_asn"]
    return {"country": {key: value for key, value in country.items() if key != "user_country"},
            "city": city,
            "infrastructure": {"server_country": countries["server_country"], "cross_region": bool(country["user_country"] and countries["server_country"] and country["user_country"] != countries["server_country"])},
            "asn": {"number": origin.get("number") if origin else None, "organization": origin.get("organization") if origin else None,
                    "source": "origin_asn", "candidates": asns}}
