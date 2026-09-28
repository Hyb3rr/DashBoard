"""Read-only Vietnam province profile assembly with explicit missingness."""
from __future__ import annotations

import csv
import json
import math
import re
import unicodedata
from pathlib import Path

from ..core.vietnam_geography import PROVINCES
from ..core.city_overall_opportunity import score_rows

ROOT = Path(__file__).resolve().parents[2]
FOUNDATION = ROOT / "data/market/vietnam_foundation"
ENRICHMENT = ROOT / "data/market/vietnam_province_enrichment"
CURRENT_INDICATORS = ENRICHMENT / "province_current_indicators.json"
FDI_STOCK = ENRICHMENT / "province_fdi_stock_context.json"
INDUSTRIAL_PRESENCE = ENRICHMENT / "province_industrial_presence_context.json"


def _load(path: Path, default):
    """Load a JSON source file or return its explicit missing-data default."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def _key(value: str) -> str:
    """Normalize province labels for safe crosswalk lookup."""
    # NFKD drops Vietnamese Đ entirely ("Điện" -> "iện"). Transliterate it
    # before accent folding, then normalize punctuation used by NSO labels.
    value = str(value).replace("Đ", "D").replace("đ", "d")
    value = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode()
    return " ".join(re.sub(r"[^a-z0-9]+", " ", value.lower()).split())


def _validated_iip_aliases() -> dict[str, set[str]]:
    """Return current-safe IIP aliases while excluding merged historical provinces."""
    crosswalk = _load(ROOT / "schemas/vietnam_province_crosswalk.json", {"entries": []})
    aliases = {unit["code"]: set() for unit in PROVINCES}
    for entry in crosswalk.get("entries", []):
        if entry.get("old_code") != entry.get("new_code"):
            continue
        if entry.get("relation") not in {"unchanged", "renamed"} or entry.get("aggregation") != "identity":
            continue
        code = entry.get("new_code")
        if code in aliases:
            aliases[code].update({_key(entry.get("old_name", "")), _key(entry.get("new_name", ""))})
    return aliases


def _latest_iip() -> dict[str, dict]:
    """Load the latest usable IIP observations through identity-safe aliases."""
    try:
        with (FOUNDATION / "nso_pxweb/E07.02.px.csv").open(encoding="utf-8-sig", newline="") as handle:
            rows = list(csv.DictReader(handle))
    except FileNotFoundError:
        return {}
    aliases = _validated_iip_aliases()
    names_to_codes = {name: code for code, names in aliases.items() for name in names}
    manifest = _load(FOUNDATION / "manifest.json", {})
    manifest_row = next((row for row in manifest.get("reports", []) if row.get("table") == "E07.02.px"), {})
    observations = {}
    for row in rows:
        source_name = row.get("Cities, provincies") or next(iter(row.values()), "")
        code = names_to_codes.get(_key(source_name))
        raw_value = row.get("Prel. 2024")
        try:
            value_is_numeric = raw_value not in (None, "", "..") and math.isfinite(float(raw_value))
        except (TypeError, ValueError):
            value_is_numeric = False
        if code and value_is_numeric:
            observations[code] = {
                "value": raw_value,
                "reference_period": "Prel. 2024",
                "source_name": "NSO Industry E07.02",
                "indicator_name": "Industrial production index (IIP)",
                "source_url": manifest_row.get("source_url"),
                "retrieved_at": manifest.get("retrieved_at"),
                "source_geography": source_name.strip(),
                "geography_basis": "NSO E07.02 source province label; identity/rename crosswalk only",
            }
    return observations


def _index_records(records: list[dict]) -> dict[str, dict]:
    """Index province source records by their canonical geography identifier."""
    return {row["geo_unit_id"]: row for row in records if row.get("geo_unit_id")}


def _latest_fdi_rows(records: list[dict]) -> tuple[str | None, dict[str, dict], dict[str, dict]]:
    """Select each province's latest FDI source row and latest usable value."""
    latest_period = max((row.get("reference_period") for row in records if row.get("reference_period")), default=None)
    latest_by_code: dict[str, dict] = {}
    usable_by_code: dict[str, dict] = {}
    for row in records:
        code = row.get("geo_unit_id")
        if not code:
            continue
        period = str(row.get("reference_period", ""))
        if code not in latest_by_code or period > str(latest_by_code[code].get("reference_period", "")):
            latest_by_code[code] = row
        if row.get("total_registered_fdi_usd_million") is not None and (
            code not in usable_by_code
            or period > str(usable_by_code[code].get("reference_period", ""))
        ):
            usable_by_code[code] = row
    return latest_period, usable_by_code, latest_by_code


def _coverage(provinces: list[dict]) -> tuple[dict, dict]:
    """Summarize available province indicators and source coverage."""
    fields = ("iip", "total_registered_fdi_usd_million", "industrial_park_count", "operating_industrial_park_count", "total_area_ha", "occupancy_rate_pct", "tenant_count", "leased_land_ha", "relevant_enterprises")
    coverage = {field: _coverage_count(provinces, field) for field in fields}
    detail = _coverage_detail(provinces, coverage)
    return coverage, detail


def _coverage_count(provinces: list[dict], field: str) -> int:
    """Count provinces with the requested evidence field available."""
    if field == "iip":
        return sum(row["status"]["iip"] == "available" for row in provinces)
    if field == "total_registered_fdi_usd_million":
        return sum(row["status"]["fdi"] == "available" for row in provinces)
    if field == "relevant_enterprises":
        return sum(row["status"]["relevant_enterprises"] == "available" for row in provinces)
    return sum(row["industrial_park_context"].get(field) is not None for row in provinces)


def _coverage_detail(provinces: list[dict], coverage: dict) -> dict:
    """Build labeled availability summaries for province evidence sources."""
    total = len(provinces)
    iip_values = [row["manufacturing_activity"]["iip"] for row in provinces]
    current_fdi_status = [row["province_investment_momentum"]["current_period"]["status"] for row in provinces]
    stock_status = [row["province_investment_momentum"]["cumulative_stock"]["status"] for row in provinces]
    return {
        "relevant_enterprises": {"label": "Relevant enterprises", "available": coverage["relevant_enterprises"], "total": total, "source_status": "complete" if coverage["relevant_enterprises"] == total else "partial"},
        "iip": {"label": "Industrial production (IIP), current", "available": sum(value is not None for value in iip_values), "total": total, "source_status": "complete" if all(value is not None for value in iip_values) else "partial"},
        "total_registered_fdi_usd_million": {"label": "Investment momentum (FDI), current", "available": sum(status == "published" for status in current_fdi_status), "reported_without_numeric": sum(status == "reported_no_numeric_value" for status in current_fdi_status), "missing": sum(status not in {"published", "reported_no_numeric_value"} for status in current_fdi_status), "source_observations": total, "total": total, "source_status": "complete"},
        "fdi_stock_cumulative_usd_million": {"label": "Cumulative FDI stock", "available": sum(status == "published" for status in stock_status), "total": total, "source_status": "complete" if all(status == "published" for status in stock_status) else "not_ingested"},
        "industrial_park_count": {"label": "Industrial parks · count", "available": coverage["industrial_park_count"], "total": total, "source_status": "partial"},
        "total_area_ha": {"label": "Industrial parks · area", "available": coverage["total_area_ha"], "total": total, "source_status": "partial"},
        "communes_with_industrial_park": {"label": "Industrial infrastructure proxy · communes with KCN", "available": sum(row["industrial_infrastructure_context"].get("communes_with_industrial_park") is not None for row in provinces), "total": total, "source_status": "rejected_source_integrity"},
    }


def _attach_overall_scores(provinces: list[dict], include_overall: bool) -> None:
    """Attach authoritative province scores or explicit unavailable states."""
    overall_scores = score_rows(provinces) if include_overall else {}
    from ..core.city_overall_opportunity import GROUP_WEIGHTS

    for row in provinces:
        row["city_overall_opportunity"] = overall_scores.get(row["geo_unit_id"], {
            "score": None, "evidence_coverage": 0, "coverage": 0, "available_groups": [],
            "missing_groups": list(GROUP_WEIGHTS), "components": {},
            "score_type": "unavailable", "status": "snapshot_unavailable",
        })


def _load_profile_sources() -> dict:
    """Load province evidence files and index each source by canonical unit ID."""
    fdi = _load(ENRICHMENT / "province_fdi_context.json", {"records": []}).get("records", [])
    park_rows = _load(ENRICHMENT / "province_industrial_park_context.json", {"records": []}).get("records", [])
    enterprise_payload = _load(ENRICHMENT / "province_enterprise_context.json", {"records": []})
    current_payload = _load(CURRENT_INDICATORS, {"records": []})
    stock_payload = _load(FDI_STOCK, {"records": [], "fetch_status": "not_ingested"})
    presence_payload = _load(INDUSTRIAL_PRESENCE, {"records": [], "fetch_status": "not_ingested"})
    latest_period, fdi_by_code, fdi_latest_by_code = _latest_fdi_rows(fdi)
    return {
        "latest_period": latest_period,
        "fdi_by_code": fdi_by_code,
        "fdi_latest_by_code": fdi_latest_by_code,
        "park_by_code": _index_records(park_rows),
        "enterprise_by_code": _index_records(enterprise_payload.get("records", [])),
        "current_by_code": _index_records(current_payload.get("records", [])),
        "stock_by_code": _index_records(stock_payload.get("records", [])),
        "presence_by_code": _index_records(presence_payload.get("records", [])),
        "iip_by_code": _latest_iip(),
        "iip_aliases": _validated_iip_aliases(),
        "enterprise_payload": enterprise_payload,
    }


def _manufacturing_context(current: dict | None, iip: dict | None, limitation: str | None) -> dict:
    """Build current IIP evidence with legacy observations kept for display."""
    source = current or iip or {}
    return {
        "iip": current.get("iip_yoy_pct") if current else (iip.get("value") if iip else None),
        "current_iip_yoy_pct": current.get("iip_yoy_pct") if current else None,
        "reference_period": source.get("reference_period"),
        "source_name": source.get("source_name"),
        "indicator_name": "Industrial production index (IIP), year-on-year" if current else (iip.get("indicator_name", "Industrial production index (IIP)") if iip else "Industrial production index (IIP)"),
        "source_url": source.get("source_url"),
        "retrieved_at": source.get("retrieved_at"),
        "source_geography": source.get("source_geography"),
        "geography_basis": source.get("geography_basis"),
        "limitation": limitation,
        "historical_legacy_iip": iip,
    }


def _investment_context(fdi_row: dict | None, fdi_source: dict, latest_period: str | None,
                        current: dict | None, stock: dict | None) -> dict:
    """Build current-flow and cumulative-stock FDI evidence for one province."""
    return {
        "total_registered_fdi_usd_million": fdi_row.get("total_registered_fdi_usd_million") if fdi_row else None,
        "reference_period": fdi_row.get("reference_period") if fdi_row else None,
        "latest_source_period": latest_period,
        "current_period": _current_fdi_context(current),
        "cumulative_stock": _fdi_stock_context(stock),
        **_source_metadata(fdi_source),
    }


def _current_fdi_context(current: dict | None) -> dict:
    """Project the latest registered-investment observation and provenance."""
    return {
        "value": current.get("fdi_registered_period_usd_million") if current else None,
        "status": current.get("fdi_status") if current else "not_ingested",
        "reference_period": current.get("reference_period") if current else None,
        "source_name": current.get("source_name") if current else None,
        "source_url": current.get("source_url") if current else None,
        "retrieved_at": current.get("retrieved_at") if current else None,
        "source_geography": current.get("source_geography") if current else None,
        "unit": "USD million",
    }


def _fdi_stock_context(stock: dict | None) -> dict:
    """Project cumulative investment stock or its explicit missing-state metadata."""
    source = stock or {}
    value = source.get("fdi_stock_cumulative_usd_million")
    return {
        "value": value,
        "status": source.get("status") or ("published" if value is not None else "not_ingested"),
        "reference_period": source.get("reference_period"),
        "source_name": source.get("source_name"),
        "source_url": source.get("source_url") or FDI_STOCK.name,
        "retrieved_at": source.get("retrieved_at"),
        "source_geography": source.get("source_geography"),
        "unit": source.get("unit") or "USD million",
        "limitation": source.get("limitation") or "FIA Appendix III attachment has not been ingested.",
    }


def _source_metadata(row: dict) -> dict:
    """Select source provenance fields shared by province market evidence."""
    keys = ("source_name", "source_url", "retrieved_at", "source_geography", "geography_basis",
            "unit", "raw_value", "transformation_method", "confidence")
    return {key: row.get(key) for key in keys}


def _enterprise_context(row: dict | None) -> dict:
    """Build enterprise-track provenance and its missing-evidence limitation."""
    source = row or {}
    limitation = (source.get("limitations") or ["No enterprise observation is available for this province."])[0] if row else "No enterprise observation is available for this province."
    return {
        "tracks": source.get("tracks", {}),
        "source_name": source.get("source_name"),
        "source_url": source.get("source_url"),
        "retrieved_at": source.get("retrieved_at"),
        "source_geography": source.get("source_geography"),
        "geography_basis": source.get("geography_basis"),
        "taxonomy_version": source.get("taxonomy_version"),
        "limitation": limitation,
    }


def _park_context(row: dict | None) -> dict:
    """Build industrial-park measures, provenance, and missing-data explanation."""
    measure_fields = ("industrial_park_count", "operating_industrial_park_count", "total_area_ha",
                      "occupancy_rate_pct", "tenant_count", "leased_land_ha")
    provenance_fields = ("reference_period", "source_name", "source_url", "retrieved_at",
                         "source_geography", "geography_basis", "unit", "raw_value",
                         "transformation_method", "confidence")
    context = {key: row.get(key) if row else None for key in measure_fields}
    context.update({key: (row or {}).get(key) for key in provenance_fields})
    context["limitation"] = (row or {}).get("limitation") or "No official industrial-park observation is available for this province."
    return context


def _fdi_limitation(fdi: dict | None, latest: dict | None, latest_period: str | None) -> str:
    """Explain missing FDI values or a province lagging the latest source period."""
    limitation = (fdi or latest or {}).get("limitation") or "No FDI observation is available for this province."
    if fdi and fdi.get("reference_period") != latest_period:
        return f"Latest source period {latest_period} has no usable provincial value; showing the latest usable observation. {limitation}"
    return limitation


def _iip_limitation(code: str, current: dict | None, iip: dict | None, aliases: dict) -> str | None:
    """Explain missing current-period IIP evidence without reusing merged boundaries."""
    if current:
        return current.get("limitation")
    if iip:
        return None
    if aliases.get(code):
        return "No direct observation in E07.02 for this current/identity geography."
    return "No direct observation for the current 2025 boundary; legacy merged observations are not carried forward."


def _infrastructure_context(presence: dict | None) -> dict:
    """Project industrial-infrastructure presence measures and provenance."""
    fields = ("communes_total", "communes_with_industrial_park", "commune_ip_presence_rate_pct",
              "reference_period", "source_name", "source_url", "retrieved_at", "source_geography",
              "geography_basis", "unit", "raw_value", "transformation_method", "confidence", "limitation")
    return {key: (presence or {}).get(key) for key in fields}


def _province_status(current: dict | None, iip: dict | None, fdi: dict | None,
                     park: dict | None, enterprise: dict | None) -> dict:
    """Derive availability flags using the profile's established completeness rules."""
    return {
        "iip": "available" if current and current.get("iip_yoy_pct") is not None else ("available" if iip else "unknown"),
        "fdi": "available" if current and current.get("fdi_status") == "published" else ("available" if fdi and fdi.get("total_registered_fdi_usd_million") is not None else "unknown"),
        "industrial_parks": "available" if park and park.get("industrial_park_count") is not None else "unknown",
        "relevant_enterprises": "available" if enterprise and all((enterprise.get("tracks", {}).get(track) or {}).get("value") is not None for track in ("woodworking", "metalworking")) else "unknown",
    }


def _province_profile_row(unit: dict, sources: dict) -> dict:
    """Assemble one canonical province row from its indexed source evidence."""
    code, name = unit["code"], unit["name"]
    fdi = sources["fdi_by_code"].get(code)
    fdi_latest = sources["fdi_latest_by_code"].get(code)
    park = sources["park_by_code"].get(code)
    enterprise = sources["enterprise_by_code"].get(code)
    iip = sources["iip_by_code"].get(code)
    current = sources["current_by_code"].get(code)
    stock = sources["stock_by_code"].get(code)
    presence = sources["presence_by_code"].get(code)
    park_context = _park_context(park)
    fdi_limitation = _fdi_limitation(fdi, fdi_latest, sources["latest_period"])
    iip_limitation = _iip_limitation(code, current, iip, sources["iip_aliases"])
    fdi_source = fdi or fdi_latest or {}
    return {
        "geo_unit_id": code,
        "province_name": name,
        "unit_type": unit["type"],
        "manufacturing_activity": _manufacturing_context(current, iip, iip_limitation),
        "province_investment_momentum": _investment_context(fdi, fdi_source, sources["latest_period"], current, stock) | {"limitation": fdi_limitation},
        "relevant_enterprises": _enterprise_context(enterprise),
        "industrial_park_context": park_context,
        "industrial_infrastructure_context": _infrastructure_context(presence),
        "status": _province_status(current, iip, fdi, park, enterprise),
    }


def build_vietnam_province_profile(*, include_overall: bool = True) -> dict:
    """Assemble canonical Vietnam province evidence and optional overall scores."""
    sources = _load_profile_sources()
    provinces = [_province_profile_row(unit, sources) for unit in PROVINCES]
    coverage, coverage_detail = _coverage(provinces)
    _attach_overall_scores(provinces, include_overall)
    enterprise_payload = sources["enterprise_payload"]
    enterprise_metadata = enterprise_payload.get("source", {})
    return {
        "scope": "VN",
        "geography_version": "vn-province-canonical-2025-1",
        "no_composite_score": False,
        "city_overall_score_version": "city-overall-v1",
        "latest_fdi_period": sources["latest_period"],
        "enterprise_source": {"source_name": enterprise_metadata.get("source_name"), "source_url": enterprise_metadata.get("source_url"), "retrieved_at": enterprise_payload.get("retrieved_at"), "taxonomy_version": enterprise_payload.get("taxonomy_version"), "complete": enterprise_payload.get("complete", False)},
        "latest_enterprise_retrieved_at": enterprise_payload.get("retrieved_at"),
        "coverage": coverage,
        "coverage_detail": coverage_detail,
        "provinces": provinces,
    }
