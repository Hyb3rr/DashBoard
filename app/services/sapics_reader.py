"""Read SAPICS MMDB releases; no runtime GeoIP network calls."""
from __future__ import annotations

import ipaddress
import json
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


def lookup(ip: str) -> dict:
    ipaddress.ip_address(ip)
    countries = {name: _country(name, ip) for name in ("user_country", "server_country", "geolite2_country", "dbip_country", "iptoasn_country")}
    cities = {name: _city(name, ip) for name in ("geolite2_city", "dbip_city")}
    asns = {name: _asn(name, ip) for name in ("origin_asn", "geolite2_asn", "dbip_asn", "iptoasn_asn")}
    user = countries["user_country"]
    city = cities["geolite2_city"] or cities["dbip_city"]
    city_distance = _distance(cities["geolite2_city"], cities["dbip_city"])
    city_conflict = city_distance is not None and city_distance > 25
    city_severity = "high" if city_distance and city_distance > 100 else "medium" if city_conflict else "none"
    others = [v for k, v in countries.items() if k not in {"user_country", "server_country"} and v]
    country_conflict = bool(user and others and any(v != user for v in others))
    country_severity = "high" if country_conflict else "none"
    origin = asns["origin_asn"]
    return {"country": {"value": user, "source": "sapics_user_country", "conflict": country_conflict,
                         "conflict_severity": country_severity, "candidates": countries},
            "city": {"value": city.get("city") if city else None, "source": "geolite2" if cities["geolite2_city"] else "dbip",
                     "state": city.get("state") if city else None, "latitude": city.get("latitude") if city else None,
                     "longitude": city.get("longitude") if city else None, "timezone": city.get("timezone") if city else None,
                     "conflict": city_conflict, "conflict_severity": city_severity, "distance_km": round(city_distance, 1) if city_distance else None,
                     "candidates": cities},
            "infrastructure": {"server_country": countries["server_country"], "cross_region": bool(user and countries["server_country"] and user != countries["server_country"])},
            "asn": {"number": origin.get("number") if origin else None, "organization": origin.get("organization") if origin else None,
                    "source": "origin_asn", "candidates": asns}}
