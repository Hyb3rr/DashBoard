"""Pure transformations for canonicalizing local IP geolocation evidence."""

from ..services.geo_normalization import (
    normalize_geoip,
    normalize_geofeed,
    normalize_ip2region,
    normalize_rir,
    normalize_sapics_country,
)


def normalize_geo_candidates(geo: dict, sapics: dict, ip2region: dict) -> tuple[list[dict], dict, bool]:
    """Normalize local geo claims and keep registration separate from operational location."""
    sap_country = sapics.get("country", {})
    sap_city = sapics.get("city", {})
    normalized = [
        normalize_sapics_country(source, value)
        for source, value in (sap_country.get("candidates") or {}).items()
        if value
    ]
    normalized.extend(
        normalize_geoip(source.removesuffix("_city"), value)
        for source, value in (sap_city.get("candidates") or {}).items()
        if value
    )
    owner_override = False
    if geo.get("country_code"):
        owner_override = any("geofeed" in str(source).lower() for source in geo.get("sources", []))
        normalized.append(
            normalize_geofeed(geo.get("country_code"), region=geo.get("region"), city=geo.get("city"), verified=True)
            if owner_override else normalize_geoip("global_geo", geo)
        )
    registration = geo.get("registration") or {}
    if registration.get("country_code"):
        normalized.append(normalize_rir(registration.get("source", "unknown"), registration.get("country_code")))
    if ip2region:
        normalized.append(normalize_ip2region(ip2region))
    return normalized, registration, owner_override


def apply_geo_resolution(canonical: dict, validated: list[dict], registration: dict, geo: dict,
                         sapics: dict, ip2region: dict, owner_override: bool, result: dict,
                         field_sources: dict, sources: list[str]) -> None:
    """Write canonical location, conflict metadata, and selected field provenance."""
    resolved = canonical["resolved"]
    selected = {
        "country": resolved.get("country_code"),
        "country_code": resolved.get("country_code"),
        "city": resolved.get("city"),
        "latitude": resolved.get("latitude"),
        "longitude": resolved.get("longitude"),
    }
    status = canonical["status"]
    location_status = "disputed" if "disputed" in status.values() else "resolved_with_conflict" if "probable" in status.values() else "resolved"
    country_candidates = canonical["candidates"].get("country", [])
    city_candidates = canonical["candidates"].get("city", [])
    sap_country = sapics.get("country", {})
    sap_city = sapics.get("city", {})
    result["network_location"] = {
        **selected,
        "coordinate_granularity": "city" if selected["latitude"] is not None and selected["longitude"] is not None else "unknown",
        "confidence": canonical["confidence"].get("country") or 0,
        "disputed": location_status == "disputed",
        "location_status": location_status,
        "scope": "network",
        "sources": [record.get("source") for record in validated if record.get("scope") == "network_operational"],
        "confidence_breakdown": canonical["confidence"],
        "registration": registration,
        "allocation_pattern": geo.get("allocation_pattern", "unknown"),
        "volatile_location": geo.get("volatile_location", False),
        "geo": sapics,
        "ip2region": ip2region,
        "canonical_resolution": canonical,
        "country_conflict": len(country_candidates) > 1,
        "country_status": status.get("country", "unknown"),
        "country_conflict_severity": sap_country.get("conflict_severity", "none"),
        "city_conflict": status.get("city") == "disputed" or bool(sap_city.get("conflict")),
        "city_status": status.get("city", "unknown"),
        "city_conflict_severity": sap_city.get("conflict_severity", "none"),
        "coordinate_conflict": status.get("coordinates") == "disputed" or bool(sap_city.get("coordinate_conflict")),
        "cross_region_infrastructure": sapics.get("infrastructure", {}).get("cross_region", False),
    }
    for field, value in selected.items():
        if value is not None:
            result[field] = value
            field_sources[field] = "SAPICS" if not owner_override else "owner-declared + SAPICS"
    for field in ("ip_prefix", "network_type"):
        if geo.get(field) is not None:
            result[field] = geo[field]
            field_sources[field] = ", ".join(geo.get("sources", [])) or "geo resolver"
    result["location_confidence"] = geo.get("confidence", 0)
    result["location_disputed"] = bool(geo.get("disputed"))
    result["location_scope"] = geo.get("scope", "network")
    sources.append("global geo resolver")
