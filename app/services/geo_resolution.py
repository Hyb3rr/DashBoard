"""Weighted, hierarchical resolution of validated GeoIP claims."""

from __future__ import annotations

from collections import defaultdict
import math
from typing import Any, Iterable

from .geonames_hierarchy import GeoNamesHierarchy


BASE_TRUST = {
    "self_published": 1.0,
    "commercial_geoip": 0.6,
    "owner_declared": 0.6,
    "registration": 0.2,
    "context_validation": 0.0,
}


def _family(source: str) -> str:
    """Map provider names to independent reliability families."""
    value = str(source).lower()
    if "geolite" in value or "maxmind" in value:
        return "maxmind"
    if "dbip" in value:
        return "dbip"
    if value.startswith("sapics:"):
        return "sapics"
    return value.split(":", 1)[0]


def _distance(a: dict[str, Any], b: dict[str, Any]) -> float | None:
    """Calculate great-circle distance between two coordinate records."""
    if any(a.get(key) is None or b.get(key) is None for key in ("latitude", "longitude")):
        return None
    radius = 6371.0
    p1, p2 = math.radians(float(a["latitude"])), math.radians(float(b["latitude"]))
    dp = math.radians(float(b["latitude"]) - float(a["latitude"]))
    dl = math.radians(float(b["longitude"]) - float(a["longitude"]))
    h = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * radius * math.asin(math.sqrt(h))


def _distance_penalty(distance: float | None) -> float:
    """Reduce coordinate confidence when competing points are far apart."""
    if distance is None:
        return 1.0
    if distance < 100:
        return 0.85
    if distance <= 1000:
        return 0.7
    return 0.5


def _weight(record: dict[str, Any], reliability: dict[str, float]) -> float:
    """Calculate one record's trust weight after provenance penalties."""
    base = BASE_TRUST.get(record.get("source_type"), 0.0)
    factor = reliability.get(_family(record.get("source", "")), 1.0)
    duplicate_penalty = 0.5 if record.get("possibly_duplicate_of") else 1.0
    stale_penalty = 0.75 if record.get("invalid_reason") == "stale_database_version" else 1.0
    return base * factor * duplicate_penalty * stale_penalty


def _status(confidence: float | None, runner_up: float | None = None,
            conflict_distance_km: float | None = None) -> str:
    """Translate confidence and disagreement into a resolution status."""
    if confidence is None:
        return "unknown"
    if (runner_up is not None and abs(confidence - runner_up) < 0.1
            and (conflict_distance_km is None or conflict_distance_km >= 100)):
        return "disputed"
    if confidence >= 0.75:
        return "resolved"
    if confidence >= 0.4:
        return "probable"
    return "disputed"


def _independent_records(records: Iterable[dict[str, Any]], key: str,
                         reliability: dict[str, float]) -> list[dict[str, Any]]:
    """Collapse adapter/cache records to one representative per source lineage."""
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        if record.get(key) not in (None, ""):
            groups[str(record.get("derived_from") or record.get("source"))].append(record)
    representatives = []
    for group in groups.values():
        representative = max(group, key=lambda item: (
            _weight(item, reliability), str(item.get("source", ""))
        ))
        representative = dict(representative)
        representative["correlated_sources"] = sorted(
            {str(item.get("source")) for item in group if item.get("source")}
        )
        representatives.append(representative)
    return representatives


def _candidate_rows(records: Iterable[dict[str, Any]], key: str, reliability: dict[str, float]) -> list[dict[str, Any]]:
    """Group independent evidence by value and rank candidates by confidence."""
    independent = _independent_records(records, key, reliability)
    groups: dict[Any, list[dict[str, Any]]] = defaultdict(list)
    for record in independent:
        value = record.get(key)
        if value not in (None, ""):
            groups[value].append(record)
    total = sum(_weight(record, reliability) for group in groups.values() for record in group)
    rows = []
    for value, group in groups.items():
        weight_sum = sum(_weight(record, reliability) for record in group)
        sources = []
        for record in group:
            sources.extend(record.get("correlated_sources") or [record.get("source")])
        rows.append({"value": value, "confidence": round((weight_sum / total) * 100, 2) if total else 0.0,
                     "sources": sorted({source for source in sources if source}), "_records": group,
                     "country_codes": sorted({str(record.get("country_code")).upper() for record in group if record.get("country_code")}),
                     "_confidence": weight_sum / total if total else 0.0})
    return sorted(rows, key=lambda row: (-row["_confidence"], str(row["value"])))


def _normalize_hierarchy_records(records: list[dict[str, Any]], hierarchy: GeoNamesHierarchy | None) -> list[dict[str, Any]]:
    """Replace locality labels only when hierarchy context proves a parent."""
    if hierarchy is None:
        return records
    normalized = []
    for original in records:
        record = dict(original)
        city = record.get("city")
        parent_ids = record.get("hierarchy_parent_ids")
        if city and parent_ids and record.get("country_code"):
            place = hierarchy.resolve(city, country_code=record["country_code"], parent_ids=set(parent_ids))
            parent = hierarchy.canonical_city_parent(place) if place else None
            if parent:
                record["raw_city"] = city
                record["city"] = parent.get("name")
                record["geo_hierarchy"] = {
                    "provider": "geonames",
                    "version": hierarchy.version,
                    "raw_city": city,
                    "matched_place_id": place["id"],
                    "parent_chain": place.get("parents", []),
                    "canonical_parent_id": parent["id"],
                    "explanation": "unique GeoNames place with supplied country and parent context",
                }
        normalized.append(record)
    return normalized


def _resolve_country(valid, reliability):
    """Resolve the strongest country candidate and its evidence status."""
    country_rows = _candidate_rows(valid, "country_code", reliability)
    geofeed_rows = [row for row in country_rows if any(record.get("source_type") == "self_published" and record.get("confidence_hint") == 1.0 for record in row["_records"])]
    if geofeed_rows:
        winner = geofeed_rows[0]
        winner["_confidence"] = 1.0
        winner["confidence"] = 100.0
        country_rows = [winner] + [row for row in country_rows if row is not winner]
    country_confidence = country_rows[0]["_confidence"] if country_rows else None
    country_status = _status(country_confidence, country_rows[1]["_confidence"] if len(country_rows) > 1 else None)
    country_value = country_rows[0]["value"] if country_status == "resolved" else None
    return country_rows, country_confidence, country_status, country_value


def _resolve_city(valid, reliability):
    """Resolve the strongest city candidate while accounting for disagreement."""
    city_rows = _candidate_rows([record for record in valid if record.get("coordinate_granularity") == "city"], "city", reliability)
    city_confidence = city_rows[0]["_confidence"] if city_rows else None
    city_distance = None
    if len(city_rows) > 1 and city_rows[0]["_records"] and city_rows[1]["_records"]:
        city_distance = _distance(city_rows[0]["_records"][0], city_rows[1]["_records"][0])
    city_status = _status(city_confidence, city_rows[1]["_confidence"] if len(city_rows) > 1 else None, city_distance)
    city_value = city_rows[0]["value"] if city_status == "resolved" else None
    return city_rows, city_confidence, city_status, city_value


def _resolve_coordinates(valid, city_rows, city_confidence, city_status, city_value, reliability):
    """Select a city coordinate only when its confidence clears the resolve gate."""
    coordinate_rows = _candidate_rows([record for record in valid if record.get("coordinate_granularity") == "city" and (city_value is None or record.get("city") == city_value)], "source", reliability)
    coordinate_confidence = None
    selected = None
    if city_value and city_rows and city_status == "resolved":
        selected = next((record for record in city_rows[0]["_records"] if record.get("city") == city_value), None)
        runner_up = next((record for row in city_rows[1:] for record in row["_records"]), None)
        distance = _distance(selected, runner_up) if selected and runner_up else None
        coordinate_confidence = city_confidence * _distance_penalty(distance) if city_confidence is not None else None
        if coordinate_confidence < 0.75:
            selected = None
    coordinate_status = _status(coordinate_confidence) if city_status == "resolved" else "unknown"
    if coordinate_status != "resolved":
        selected = None
    return coordinate_rows, coordinate_confidence, coordinate_status, selected


def _candidate_response(country_rows, excluded, city_rows):
    """Build public country and city candidate lists without internal scores."""
    candidates_country = [{key: value for key, value in row.items() if not key.startswith("_")} for row in country_rows]
    for record in excluded:
        candidates_country.append({"value": record.get("country_code"), "confidence": 0, "sources": [record.get("source")], "excluded_reason": record.get("invalid_reason")})
    candidates_city = []
    for row in city_rows:
        public = {key: value for key, value in row.items() if not key.startswith("_")}
        public["hierarchy"] = [record.get("geo_hierarchy") for record in row.get("_records", []) if record.get("geo_hierarchy")]
        candidates_city.append(public)
    return candidates_country, candidates_city


def resolve_geo_records(records: list[dict[str, Any]], *, registration_context: dict[str, Any] | None = None,
                       evidence: list[dict[str, Any]] | None = None, reliability: dict[str, float] | None = None,
                       hierarchy: GeoNamesHierarchy | None = None) -> dict[str, Any]:
    """Resolve validated geo claims into canonical country, city, and coordinates."""
    reliability = reliability or {}
    records = _normalize_hierarchy_records(records, hierarchy)
    operational = [record for record in records if record.get("scope") == "network_operational" and record.get("source_type") not in {"registration", "context_validation"}]
    valid = [record for record in operational if record.get("valid", True)]
    excluded = [record for record in operational if not record.get("valid", True)]
    country_rows, country_confidence, country_status, country_value = _resolve_country(valid, reliability)
    city_rows, city_confidence, city_status, city_value = _resolve_city(valid, reliability)
    coordinate_rows, coordinate_confidence, coordinate_status, selected = _resolve_coordinates(
        valid, city_rows, city_confidence, city_status, city_value, reliability
    )
    candidates_country, candidates_city = _candidate_response(country_rows, excluded, city_rows)
    return {
        "resolved": {"country_code": country_value, "city": city_value if coordinate_status == "resolved" else None,
                      "latitude": selected.get("latitude") if selected else None, "longitude": selected.get("longitude") if selected else None},
        "status": {"country": country_status, "city": city_status, "coordinates": coordinate_status},
        "confidence": {"country": round(country_confidence * 100, 2) if country_confidence is not None else None,
                       "city": round(city_confidence * 100, 2) if city_confidence is not None and city_status != "unknown" else None,
                       "coordinates": round(coordinate_confidence * 100, 2) if coordinate_confidence is not None else None},
        "candidates": {"country": candidates_country, "city": candidates_city, "coordinates": coordinate_rows},
        "registration_context": registration_context or {},
        "evidence": evidence or [],
        "coverage": {"operational_sources_total": len(operational), "operational_sources_valid": len(valid),
                      "agreeing_country_sources": len(country_rows[0]["_records"]) if country_rows else 0,
                      "agreeing_city_sources": len(city_rows[0]["_records"]) if city_rows else 0},
    }
