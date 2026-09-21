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
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def _key(value: str) -> str:
    # NFKD drops Vietnamese Đ entirely ("Điện" -> "iện"). Transliterate it
    # before accent folding, then normalize punctuation used by NSO labels.
    value = str(value).replace("Đ", "D").replace("đ", "d")
    value = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode()
    return " ".join(re.sub(r"[^a-z0-9]+", " ", value.lower()).split())


def _validated_iip_aliases() -> dict[str, set[str]]:
    """Return only identity/rename aliases safe for a current province index.

    A pre-2025 row from a merged province is deliberately excluded. Matching a
    legacy name to the new province name would make an old index look current.
    """
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


def build_vietnam_province_profile(*, include_overall: bool = True) -> dict:
    fdi = _load(ENRICHMENT / "province_fdi_context.json", {"records": []}).get("records", [])
    park_rows = _load(ENRICHMENT / "province_industrial_park_context.json", {"records": []}).get("records", [])
    enterprise_payload = _load(ENRICHMENT / "province_enterprise_context.json", {"records": []})
    enterprise_rows = enterprise_payload.get("records", [])
    current_payload = _load(CURRENT_INDICATORS, {"records": []})
    stock_payload = _load(FDI_STOCK, {"records": [], "fetch_status": "not_ingested"})
    presence_payload = _load(INDUSTRIAL_PRESENCE, {"records": [], "fetch_status": "not_ingested"})
    current_by_code = {row["geo_unit_id"]: row for row in current_payload.get("records", []) if row.get("geo_unit_id")}
    stock_by_code = {row["geo_unit_id"]: row for row in stock_payload.get("records", []) if row.get("geo_unit_id")}
    presence_by_code = {row["geo_unit_id"]: row for row in presence_payload.get("records", []) if row.get("geo_unit_id")}
    latest_period = max((row.get("reference_period") for row in fdi if row.get("reference_period")), default=None)
    # Prefer the newest row that contains a value for each province. A newer
    # all-null report must not hide the last usable observation.
    fdi_by_code = {}
    fdi_latest_by_code = {}
    for row in fdi:
        code = row.get("geo_unit_id")
        if not code:
            continue
        if code not in fdi_latest_by_code or str(row.get("reference_period", "")) > str(fdi_latest_by_code[code].get("reference_period", "")):
            fdi_latest_by_code[code] = row
        if row.get("total_registered_fdi_usd_million") is None:
            continue
        if code not in fdi_by_code or str(row.get("reference_period", "")) > str(fdi_by_code[code].get("reference_period", "")):
            fdi_by_code[code] = row
    park_by_code = {row["geo_unit_id"]: row for row in park_rows}
    enterprise_by_code = {row["geo_unit_id"]: row for row in enterprise_rows}
    iip_by_name = _latest_iip()
    iip_aliases = _validated_iip_aliases()
    provinces = []
    for unit in PROVINCES:
        code, name = unit["code"], unit["name"]
        fdi_row, fdi_source_row, park_row, enterprise_row, iip, current, stock, presence = fdi_by_code.get(code), fdi_latest_by_code.get(code), park_by_code.get(code), enterprise_by_code.get(code), iip_by_name.get(code), current_by_code.get(code), stock_by_code.get(code), presence_by_code.get(code)
        park_context = {key: park_row.get(key) if park_row else None for key in ("industrial_park_count", "operating_industrial_park_count", "total_area_ha", "occupancy_rate_pct", "tenant_count", "leased_land_ha")}
        park_context.update({key: (park_row or {}).get(key) for key in ("reference_period", "source_name", "source_url", "retrieved_at", "source_geography", "geography_basis", "unit", "raw_value", "transformation_method", "confidence")})
        park_context["limitation"] = (park_row or {}).get("limitation") or "No official industrial-park observation is available for this province."
        fdi_limitation = (fdi_row or fdi_source_row or {}).get("limitation") or "No FDI observation is available for this province."
        if fdi_row and fdi_row.get("reference_period") != latest_period:
            fdi_limitation = f"Latest source period {latest_period} has no usable provincial value; showing the latest usable observation. {fdi_limitation}"
        if current:
            iip_limitation = current.get("limitation")
        elif iip:
            iip_limitation = None
        elif iip_aliases.get(code):
            iip_limitation = "No direct observation in E07.02 for this current/identity geography."
        else:
            iip_limitation = "No direct observation for the current 2025 boundary; legacy merged observations are not carried forward."
        fdi_source = fdi_row or fdi_source_row or {}
        provinces.append({
            "geo_unit_id": code, "province_name": name, "unit_type": unit["type"],
            "manufacturing_activity": {"iip": current.get("iip_yoy_pct") if current else (iip.get("value") if iip else None), "current_iip_yoy_pct": current.get("iip_yoy_pct") if current else None, "reference_period": current.get("reference_period") if current else (iip.get("reference_period") if iip else None), "source_name": current.get("source_name") if current else (iip.get("source_name") if iip else None), "indicator_name": "Industrial production index (IIP), year-on-year" if current else (iip.get("indicator_name", "Industrial production index (IIP)") if iip else "Industrial production index (IIP)"), "source_url": current.get("source_url") if current else (iip.get("source_url") if iip else None), "retrieved_at": current.get("retrieved_at") if current else (iip.get("retrieved_at") if iip else None), "source_geography": current.get("source_geography") if current else (iip.get("source_geography") if iip else None), "geography_basis": current.get("geography_basis") if current else (iip.get("geography_basis") if iip else None), "limitation": iip_limitation, "historical_legacy_iip": iip},
            "province_investment_momentum": {"total_registered_fdi_usd_million": fdi_row.get("total_registered_fdi_usd_million") if fdi_row else None, "reference_period": fdi_row.get("reference_period") if fdi_row else None, "latest_source_period": latest_period, "current_period": {"value": current.get("fdi_registered_period_usd_million") if current else None, "status": current.get("fdi_status") if current else "not_ingested", "reference_period": current.get("reference_period") if current else None, "source_name": current.get("source_name") if current else None, "source_url": current.get("source_url") if current else None, "retrieved_at": current.get("retrieved_at") if current else None, "source_geography": current.get("source_geography") if current else None, "unit": "USD million"}, "cumulative_stock": {"value": stock.get("fdi_stock_cumulative_usd_million") if stock else None, "status": stock.get("status") or ("published" if stock and stock.get("fdi_stock_cumulative_usd_million") is not None else "not_ingested"), "reference_period": stock.get("reference_period") if stock else None, "source_name": stock.get("source_name") if stock else None, "source_url": stock.get("source_url") if stock else FDI_STOCK.name, "retrieved_at": stock.get("retrieved_at") if stock else None, "source_geography": stock.get("source_geography") if stock else None, "unit": stock.get("unit") if stock else "USD million", "limitation": stock.get("limitation") if stock else "FIA Appendix III attachment has not been ingested."}, "source_name": fdi_source.get("source_name"), "source_url": fdi_source.get("source_url"), "retrieved_at": fdi_source.get("retrieved_at"), "source_geography": fdi_source.get("source_geography"), "geography_basis": fdi_source.get("geography_basis"), "unit": fdi_source.get("unit"), "raw_value": fdi_source.get("raw_value"), "transformation_method": fdi_source.get("transformation_method"), "confidence": fdi_source.get("confidence"), "limitation": fdi_limitation},
            "relevant_enterprises": {"tracks": (enterprise_row or {}).get("tracks", {}), "source_name": (enterprise_row or {}).get("source_name"), "source_url": (enterprise_row or {}).get("source_url"), "retrieved_at": (enterprise_row or {}).get("retrieved_at"), "source_geography": (enterprise_row or {}).get("source_geography"), "geography_basis": (enterprise_row or {}).get("geography_basis"), "taxonomy_version": (enterprise_row or {}).get("taxonomy_version"), "limitation": ((enterprise_row or {}).get("limitations") or ["No enterprise observation is available for this province."])[0] if enterprise_row else "No enterprise observation is available for this province."},
            "industrial_park_context": park_context,
            "industrial_infrastructure_context": {key: (presence or {}).get(key) for key in ("communes_total", "communes_with_industrial_park", "commune_ip_presence_rate_pct", "reference_period", "source_name", "source_url", "retrieved_at", "source_geography", "geography_basis", "unit", "raw_value", "transformation_method", "confidence", "limitation")},
            "status": {"iip": "available" if current and current.get("iip_yoy_pct") is not None else ("available" if iip else "unknown"), "fdi": "available" if current and current.get("fdi_status") == "published" else ("available" if fdi_row and fdi_row.get("total_registered_fdi_usd_million") is not None else "unknown"), "industrial_parks": "available" if park_row and park_row.get("industrial_park_count") is not None else "unknown", "relevant_enterprises": "available" if enterprise_row and all((enterprise_row.get("tracks", {}).get(track) or {}).get("value") is not None for track in ("woodworking", "metalworking")) else "unknown"},
        })
    fields = ("iip", "total_registered_fdi_usd_million", "industrial_park_count", "operating_industrial_park_count", "total_area_ha", "occupancy_rate_pct", "tenant_count", "leased_land_ha", "relevant_enterprises")
    coverage = {}
    for field in fields:
        coverage[field] = sum(row["status"]["iip"] == "available" if field == "iip" else row["status"]["fdi"] == "available" if field == "total_registered_fdi_usd_million" else row["status"]["relevant_enterprises"] == "available" if field == "relevant_enterprises" else row["industrial_park_context"].get(field) is not None for row in provinces)
    coverage_detail = {
        "relevant_enterprises": {"label": "Relevant enterprises", "available": coverage["relevant_enterprises"], "total": len(provinces), "source_status": "complete" if coverage["relevant_enterprises"] == len(provinces) else "partial"},
        "iip": {"label": "Industrial production (IIP), current", "available": sum(row["manufacturing_activity"]["iip"] is not None for row in provinces), "total": len(provinces), "source_status": "complete" if all(row["manufacturing_activity"]["iip"] is not None for row in provinces) else "partial"},
        "total_registered_fdi_usd_million": {"label": "Investment momentum (FDI), current", "available": sum(row["province_investment_momentum"]["current_period"]["status"] == "published" for row in provinces), "reported_without_numeric": sum(row["province_investment_momentum"]["current_period"]["status"] == "reported_no_numeric_value" for row in provinces), "missing": sum(row["province_investment_momentum"]["current_period"]["status"] not in {"published", "reported_no_numeric_value"} for row in provinces), "source_observations": len(provinces), "total": len(provinces), "source_status": "complete"},
        "fdi_stock_cumulative_usd_million": {"label": "Cumulative FDI stock", "available": sum(row["province_investment_momentum"]["cumulative_stock"]["status"] == "published" for row in provinces), "total": len(provinces), "source_status": "complete" if all(row["province_investment_momentum"]["cumulative_stock"]["status"] == "published" for row in provinces) else "not_ingested"},
        "industrial_park_count": {"label": "Industrial parks · count", "available": coverage["industrial_park_count"], "total": len(provinces), "source_status": "partial"},
        "total_area_ha": {"label": "Industrial parks · area", "available": coverage["total_area_ha"], "total": len(provinces), "source_status": "partial"},
        "communes_with_industrial_park": {"label": "Industrial infrastructure proxy · communes with KCN", "available": sum(row["industrial_infrastructure_context"].get("communes_with_industrial_park") is not None for row in provinces), "total": len(provinces), "source_status": "rejected_source_integrity"},
    }
    overall_scores = score_rows(provinces) if include_overall else {}
    for row in provinces:
        row["city_overall_opportunity"] = overall_scores.get(row["geo_unit_id"], {
            "score": None, "evidence_coverage": 0, "coverage": 0, "available_groups": [],
            "missing_groups": list(__import__("app.core.city_overall_opportunity", fromlist=["GROUP_WEIGHTS"]).GROUP_WEIGHTS),
            "components": {}, "score_type": "unavailable", "status": "snapshot_unavailable",
        })
    return {"scope": "VN", "geography_version": "vn-province-canonical-2025-1", "no_composite_score": False, "city_overall_score_version": "city-overall-v1", "latest_fdi_period": latest_period, "enterprise_source": {"source_name": enterprise_payload.get("source", {}).get("source_name"), "source_url": enterprise_payload.get("source", {}).get("source_url"), "retrieved_at": enterprise_payload.get("retrieved_at"), "taxonomy_version": enterprise_payload.get("taxonomy_version"), "complete": enterprise_payload.get("complete", False)}, "latest_enterprise_retrieved_at": enterprise_payload.get("retrieved_at"), "coverage": coverage, "coverage_detail": coverage_detail, "provinces": provinces}
