"""Per-record validation for normalized GeoIP source claims."""

from __future__ import annotations

from datetime import datetime, timezone
import math
from typing import Any, Mapping


INVALID_REASONS = {
    "coordinate_country_mismatch", "null_island", "known_vendor_sentinel",
    "stale_database_version", "duplicate_of_other_source", "none",
}


def _date(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        try:
            parsed = datetime.strptime(text, "%Y-%m")
        except ValueError:
            return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _inside_bounds(record: Mapping[str, Any], bounds: Mapping[str, tuple[float, float, float, float]], padding_km: float) -> bool | None:
    code = record.get("country_code")
    lat, lon = record.get("latitude"), record.get("longitude")
    if not code or lat is None or lon is None:
        return None
    country_bounds = bounds.get(str(code).upper())
    if not country_bounds:
        return None
    min_lat, min_lon, max_lat, max_lon = country_bounds
    latitude_padding = padding_km / 111.0
    longitude_padding = padding_km / max(1.0, 111.0 * math.cos(math.radians(float(lat))))
    return min_lat - latitude_padding <= float(lat) <= max_lat + latitude_padding and min_lon - longitude_padding <= float(lon) <= max_lon + longitude_padding


def validate_records(records: list[dict[str, Any]], *, country_bounds: Mapping[str, tuple[float, float, float, float]] | None = None,
                     sentinels: Mapping[str, set[tuple[float, float]]] | None = None,
                     now: datetime | None = None, stale_after_days: int = 180,
                     boundary_padding_km: float = 50.0) -> list[dict[str, Any]]:
    """Validate each record independently, then annotate duplicate relationships."""
    now = now or datetime.now(timezone.utc)
    country_bounds = country_bounds or {}
    sentinels = sentinels or {}
    result = []
    for original in records:
        record = dict(original)
        record.update({"valid": True, "invalid_reason": "none", "is_likely_fallback_value": False})
        lat, lon = record.get("latitude"), record.get("longitude")
        pair = (float(lat), float(lon)) if lat is not None and lon is not None else None
        if pair == (0.0, 0.0):
            record.update(valid=False, invalid_reason="null_island", is_likely_fallback_value=True)
        elif pair is not None and pair in sentinels.get(str(record.get("source")), set()):
            record["is_likely_fallback_value"] = True
        inside = _inside_bounds(record, country_bounds, boundary_padding_km)
        if inside is False and record["invalid_reason"] == "none":
            record.update(valid=False, invalid_reason="coordinate_country_mismatch")
        elif pair is not None and record.get("coordinate_granularity") == "unknown":
            record["is_likely_fallback_value"] = True
        version_date = _date(record.get("database_version"))
        if version_date and (now - version_date).days > stale_after_days and record["invalid_reason"] == "none":
            record["invalid_reason"] = "stale_database_version"
        result.append(record)

    for index, record in enumerate(result):
        pair = record.get("latitude"), record.get("longitude")
        if pair[0] is None or pair[1] is None:
            continue
        duplicates = []
        for other_index, other in enumerate(result):
            if index == other_index or other.get("latitude") is None or other.get("longitude") is None:
                continue
            same_coordinates = round(float(pair[0]), 4) == round(float(other["latitude"]), 4) and round(float(pair[1]), 4) == round(float(other["longitude"]), 4)
            same_context = record.get("city") == other.get("city") and record.get("accuracy_radius_km") == other.get("accuracy_radius_km")
            if same_coordinates and same_context:
                duplicates.append(str(other.get("source")))
        if duplicates:
            record["possibly_duplicate_of"] = sorted(set(duplicates))
    return result
