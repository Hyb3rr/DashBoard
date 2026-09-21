"""Pure adapters that turn provider payloads into the GeoIP contract.

Adapters deliberately do not compare sources, choose winners, or mark conflicts.
Those decisions belong to validation and resolution phases.
"""

from __future__ import annotations

import math
import os
from typing import Any


def _text(value: Any) -> str | None:
    if value is None:
        return None
    value = str(value).strip()
    return value or None


def _country(value: Any) -> str | None:
    value = _text(value)
    return value.upper() if value and len(value) == 2 and value.isalpha() else None


def _coordinate(value: Any, minimum: float, maximum: float) -> float | None:
    try:
        value = float(value)
    except (TypeError, ValueError):
        return None
    return value if math.isfinite(value) and minimum <= value <= maximum else None


def _lineage(source: str, *, explicit: str | None = None) -> str:
    """Return the original vendor lineage, not the adapter/cache name."""
    if explicit:
        return explicit
    value = source.lower()
    for vendor in ("geolite2", "maxmind", "dbip", "ipligence"):
        if vendor in value:
            return vendor
    return value.split(":", 1)[0].split("_", 1)[0]


def _base(source: str, source_type: str, scope: str, raw_ref: str | None = None,
          *, derived_from: str | None = None) -> dict[str, Any]:
    return {
        "source": source,
        "derived_from": _lineage(source, explicit=derived_from),
        "source_type": source_type,
        "scope": scope,
        "country_code": None,
        "country_name": None,
        "region": None,
        "city": None,
        "latitude": None,
        "longitude": None,
        "coordinate_granularity": "unknown",
        "accuracy_radius_km": None,
        "confidence_hint": None,
        "observed_at": None,
        "database_version": None,
        "raw_ref": raw_ref,
    }


def normalize_sapics_country(source: str, country_code: Any, *, raw_ref: str | None = None) -> dict[str, Any]:
    """Keep SAPICS user/server country records separate; never choose between them."""
    normalized_source = str(source).strip().replace("-", "_")
    correlation_group = "sapics_network_country" if normalized_source in {"user_country", "server_country"} else _lineage(source)
    result = _base(f"sapics:{normalized_source}", "owner_declared", "network_operational", raw_ref,
                   derived_from=correlation_group)
    if correlation_group == "sapics_network_country":
        result["correlation_group"] = correlation_group
    result["country_code"] = _country(country_code)
    return result


def normalize_geoip(source: str, payload: dict[str, Any] | None, *, database_version: str | None = None,
                    raw_ref: str | None = None) -> dict[str, Any]:
    """Normalize one GeoIP vendor record without borrowing fields from another vendor."""
    payload = payload or {}
    result = _base(source, "commercial_geoip", "network_operational", raw_ref,
                   derived_from=_lineage(source))
    result.update({
        "country_code": _country(payload.get("country_code")),
        "country_name": _text(payload.get("country_name")),
        "region": _text(payload.get("region") or payload.get("state")),
        "city": _text(payload.get("city")),
        "latitude": _coordinate(payload.get("latitude"), -90, 90),
        "longitude": _coordinate(payload.get("longitude"), -180, 180),
        "accuracy_radius_km": _coordinate(payload.get("accuracy_radius_km"), 0, float("inf")),
        "confidence_hint": _coordinate(payload.get("confidence_hint"), 0, 1),
        "observed_at": payload.get("observed_at"),
        "database_version": database_version or payload.get("database_version"),
    })
    radius_threshold = float(os.getenv("GEO_CITY_ACCURACY_RADIUS_KM", "100"))
    if result["latitude"] is not None and result["longitude"] is not None:
        if result["city"] and (result["accuracy_radius_km"] is None or result["accuracy_radius_km"] <= radius_threshold):
            result["coordinate_granularity"] = "city"
        else:
            result["coordinate_granularity"] = "country"
    return result


def normalize_ip2region(payload: dict[str, Any] | None, *, raw_ref: str | None = None) -> dict[str, Any]:
    payload = payload or {}
    result = _base("ip2region", "context_validation", "context_only", raw_ref,
                   derived_from="ip2region")
    result.update({
        "country_code": _country(payload.get("country_code")),
        "region": _text(payload.get("region")),
        "city": _text(payload.get("city")),
    })
    return result


def normalize_rir(source: str, country_code: Any, *, raw_ref: str | None = None) -> dict[str, Any]:
    result = _base(f"rir:{source}", "registration", "allocation_registration", raw_ref,
                   derived_from=f"rir:{_lineage(source)}")
    result["country_code"] = _country(country_code)
    return result


def normalize_geofeed(country_code: Any, *, region: Any = None, city: Any = None,
                      raw_ref: str | None = None, verified: bool = False) -> dict[str, Any]:
    result = _base("geofeed", "self_published", "network_operational", raw_ref,
                   derived_from="geofeed")
    result["country_code"] = _country(country_code)
    result["region"] = _text(region)
    result["city"] = _text(city)
    result["coordinate_granularity"] = "city" if result["city"] else "country" if result["country_code"] else "unknown"
    result["confidence_hint"] = 1.0 if verified else None
    return result
