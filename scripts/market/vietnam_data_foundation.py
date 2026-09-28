"""Download reproducible Vietnam market-intelligence source snapshots.

This command only collects and normalizes source data. It never allocates
national industry data to provinces and never computes a market score.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import urllib.request
from urllib.error import HTTPError, URLError
from datetime import datetime, timezone
from pathlib import Path


PX_BASE = "https://pxweb.nso.gov.vn/api/v1/en/Enterprise"
PX_INDUSTRY_BASE = "https://pxweb.nso.gov.vn/api/v1/en/Industry"
COMTRADE_URL = "https://comtradeapi.un.org/public/v1/preview/C/A/HS"
COMTRADE_FULL_URL = "https://comtradeapi.un.org/data/v1/get/C/A/HS"
HS_REFERENCE_URL = "https://comtradeapi.un.org/files/v1/app/reference/HS.json"
PX_TABLES = {
    "E05.03.px": "national_industry_structure",
    "E05.01.px": "national_new_enterprises_by_industry",
    "E05.07.px": "national_enterprises_with_outcomes_by_industry",
    "E05.04.px": "province_enterprise_structure",
    "E05.08.px": "province_enterprise_structure_outcomes",
    "E05.10.px": "national_industry_employment",
    "E05.11.px": "province_enterprise_employment",
    "E05.25.px": "national_enterprise_size_by_industry",
    "E05.26.px": "province_enterprise_size",
    "E05.29.px": "province_enterprise_capital_size",
    "E05.22.px": "national_industry_turnover",
    "E05.16.px": "national_industry_capital",
    "E05.23.px": "province_enterprise_turnover",
}
PX_INDUSTRY_TABLES = {
    "E07.01.px": "national_iip_by_industry",
    "E07.02.px": "province_iip",
}
HS_CODES = ("8456", "8457", "8458", "8459", "8460", "8461", "8462", "8463", "8465")
HS6_PRODUCT_MAP = {
    "laser_plasma_cutting": ("845610", "845611", "845612", "845640", "845650", "845690"),
    "machining_centre_metal": ("845710",),
    "lathe": ("845811", "845819", "845891", "845899"),
    "drilling_milling_metal": ("845910", "845921", "845929", "845931", "845939", "845940", "845941", "845949", "845951", "845959", "845961", "845969", "845970"),
    "grinding_honing": ("846011", "846012", "846019", "846021", "846022", "846023", "846024", "846029", "846031", "846039", "846040", "846090"),
    "planing_gear_cutting": ("846110", "846120", "846130", "846140", "846150", "846190"),
    "press_brake_forming": ("846210", "846211", "846219", "846221", "846222", "846223", "846224", "846225", "846226", "846229", "846231", "846232", "846233", "846239", "846241", "846242", "846249", "846251", "846259", "846261", "846262", "846263", "846269", "846290", "846291", "846299"),
    "other_metal_forming": ("846310", "846320", "846330", "846390"),
    "cnc_router": ("846520",),
    "panel_saw": ("846591",),
    "planer_moulder": ("846592",),
    "sanding_machine": ("846593",),
    "drilling_mortising": ("846595",),
    "edge_bander": ("846599",),
}


def _request(url: str, payload: dict | None = None) -> bytes:
    """Fetch one source response with the foundation client headers and timeout."""
    body = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(url, data=body, headers={"User-Agent": "IPIntel-VN-Foundation/1.0", "Content-Type": "application/json"} if body else {"User-Agent": "IPIntel-VN-Foundation/1.0"})
    with urllib.request.urlopen(request, timeout=120) as response:
        return response.read()


def _metadata(table: str, base: str = PX_BASE) -> dict:
    """Load PX-Web metadata for one table."""
    return json.loads(_request(f"{base}/{table}"))


def _all_query(metadata: dict, year: str | None = None) -> dict:
    """Build a PX-Web query selecting every dimension, optionally one year."""
    query = []
    for variable in metadata["variables"]:
        values = variable["values"]
        if variable["code"].lower() == "year" and year:
            labels = variable.get("valueTexts", [])
            index = labels.index(year) if year in labels else len(values) - 1
            values = [values[index]]
        query.append({"code": variable["code"], "selection": {"filter": "item", "values": values}})
    return {"query": query, "response": {"format": "csv"}}


def download_px(table: str, output: Path, year: str | None = None, base: str = PX_BASE, dataset: str | None = None) -> dict:
    """Download one PX-Web table and return its provenance record."""
    metadata = _metadata(table, base)
    raw = _request(f"{base}/{table}", _all_query(metadata, year))
    output.mkdir(parents=True, exist_ok=True)
    raw_path = output / f"{table}.csv"
    raw_path.write_bytes(raw)
    year_var = next((v for v in metadata.get("variables", []) if v.get("code", "").lower() == "year" or "year" in v.get("text", "").lower()), None)
    if year:
        period = year
    elif year_var:
        labels = year_var.get("valueTexts") or []
        period = labels[-1] if labels else (year_var.get("values") or [None])[-1]
    else:
        period = None
    return {"dataset": dataset or PX_TABLES.get(table, table), "table": table, "rows": max(0, raw.count(b"\n") - 1), "period": period, "source_url": f"{base}/{table}", "sha256": hashlib.sha256(raw).hexdigest()}


def download_comtrade(output: Path, years: list[int]) -> list[dict]:
    """Download annual Comtrade previews and report unavailable years explicitly."""
    output.mkdir(parents=True, exist_ok=True)
    reports = []
    for year in years:
        params = "reporterCode=704&partnerCode=0&flowCode=M&partner2Code=0&customsCode=C00&motCode=0&cmdCode=" + ",".join(HS_CODES) + f"&period={year}&maxrecords=500&format=json"
        try:
            raw = _request(f"{COMTRADE_URL}?{params}")
        except (HTTPError, URLError, TimeoutError) as exc:
            reports.append({"dataset": "vietnam_machinery_imports", "period": year, "rows": None, "status": "failed", "error": type(exc).__name__, "source_url": COMTRADE_URL, "classification": "HS6/H6", "classification_search": "HS", "reporter": "704", "partner": "0", "flow": "M", "period_parameter": str(year)})
            continue
        path = output / f"comtrade_vn_import_hs_{year}.json"
        path.write_bytes(raw)
        payload = json.loads(raw)
        rows = len(payload.get("data", []))
        reports.append({"dataset": "vietnam_machinery_imports", "period": year, "rows": rows if rows else None, "status": "loaded" if rows else "no_rows_returned", "source_url": COMTRADE_URL, "sha256": hashlib.sha256(raw).hexdigest(), "classification": "H6", "classification_search": "HS", "reporter": "704", "partner": "0", "flow": "M", "period_parameter": str(year), "query": params})
    return reports


def probe_comtrade_full(output: Path) -> dict:
    """Probe the authenticated endpoint without treating denial as missing data."""
    params = "reporterCode=704&partnerCode=0&flowCode=M&partner2Code=0&customsCode=C00&motCode=0&cmdCode=8456&period=2024&maxRecords=500&typeCode=C&freqCode=A&clCode=HS&breakdownMode=classic&includeDesc=true"
    try:
        raw = _request(f"{COMTRADE_FULL_URL}?{params}")
        payload = json.loads(raw)
        return {"endpoint": COMTRADE_FULL_URL, "status": "loaded", "rows": len(payload.get("data", [])), "query": params}
    except HTTPError as exc:
        return {"endpoint": COMTRADE_FULL_URL, "status": "access_denied_or_error", "http_status": exc.code, "query": params, "limitation": "full API requires subscription key"}
    except (URLError, TimeoutError) as exc:
        return {"endpoint": COMTRADE_FULL_URL, "status": "failed", "error": type(exc).__name__, "query": params}


def _read_rows(path: Path) -> list[dict]:
    """Read a UTF-8 CSV snapshot into row dictionaries."""
    with path.open(newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


def build_national_profiles(output: Path) -> dict:
    """Build transparent national profiles from NSO rows; no geography allocation."""
    specs = {
        "woodworking": ["Manufacture of wood and of products of wood and cork (except furniture)", "Manufacture of furniture"],
        "metalworking": ["Manufacture of basic metals", "Manufacture of fabricated metal products (except machinery and equipment)", "Manufacture of machinery and equipment n.e.c"],
    }
    datasets = {"enterprise_count": "E05.07.px.csv", "employment": "E05.10.px.csv", "enterprise_size": "E05.25.px.csv", "turnover": "E05.22.px.csv", "capital": "E05.16.px.csv"}
    profiles = {}
    for track, labels in specs.items():
        profiles[track] = {"scope": "national", "taxonomy": "VSIC2018", "activity_level": "division_level_2_broad_sector_proxy", "source_tables": {}, "industries": {}}
        for metric, filename in datasets.items():
            path = output / "nso_pxweb" / filename
            rows = _read_rows(path) if path.exists() else []
            matched = [r for r in rows if next(iter(r.values()), "") in labels]
            profiles[track]["source_tables"][metric] = filename
            profiles[track]["industries"][metric] = matched
    path = output / "national_structural_profiles.json"
    path.write_text(json.dumps(profiles, indent=2, ensure_ascii=False), encoding="utf-8")
    return {"path": str(path), "tracks": list(profiles)}


def _download_px_sources(output: Path) -> list[dict]:
    """Download enterprise and industry PX-Web tables in their established order."""
    reports = []
    for table in PX_TABLES:
        try:
            reports.append({**download_px(table, output / "nso_pxweb"), "status": "loaded"})
        except (HTTPError, URLError, TimeoutError) as exc:
            reports.append({"dataset": PX_TABLES[table], "table": table, "rows": None, "status": "failed", "error": type(exc).__name__, "source_url": f"{PX_BASE}/{table}", "limitation": "Source fetch failed; row count is unknown."})
    for table, dataset in PX_INDUSTRY_TABLES.items():
        try:
            reports.append({**download_px(table, output / "nso_pxweb", base=PX_INDUSTRY_BASE, dataset=dataset), "status": "loaded"})
        except (HTTPError, URLError, TimeoutError) as exc:
            reports.append({"dataset": dataset, "table": table, "rows": None, "status": "failed", "error": type(exc).__name__, "source_url": f"{PX_INDUSTRY_BASE}/{table}", "limitation": "Source fetch failed; row count is unknown."})
    return reports


def download_comtrade_2026_ytd(output: Path, through_month: int = 9) -> list[dict]:
    """Probe each available 2026 month; an empty response is unknown, not zero."""
    reports = []
    for month in range(1, through_month + 1):
        period = f"2026{month:02d}"
        params = "reporterCode=704&partnerCode=0&flowCode=M&partner2Code=0&customsCode=C00&motCode=0&cmdCode=" + ",".join(HS_CODES) + f"&period={period}&maxrecords=500&format=json"
        try:
            raw = _request(f"{COMTRADE_URL.replace('/C/A/', '/C/M/')}?{params}")
            payload = json.loads(raw)
            rows = len(payload.get("data", []))
            if rows:
                (output / f"comtrade_vn_import_hs_{period}.json").write_bytes(raw)
            reports.append({"dataset": "vietnam_machinery_imports", "period": period, "rows": rows if rows else None, "status": "loaded" if rows else "no_rows_returned", "source_url": COMTRADE_URL.replace('/C/A/', '/C/M/'), "classification": "H6", "classification_search": "HS", "reporter": "704", "partner": "0", "flow": "M", "period_parameter": period})
        except (HTTPError, URLError, TimeoutError) as exc:
            reports.append({"dataset": "vietnam_machinery_imports", "period": period, "rows": None, "status": "failed", "error": type(exc).__name__, "source_url": COMTRADE_URL.replace('/C/A/', '/C/M/')})
    return reports


def _build_manifest(output: Path, years: list[int], retrieved: str) -> dict:
    """Collect remaining source reports and assemble the reproducible manifest."""
    reports = _download_px_sources(output)
    reports += download_comtrade(output / "comtrade", years)
    ytd = download_comtrade_2026_ytd(output / "comtrade")
    profiles = build_national_profiles(output)
    full_api = probe_comtrade_full(output)
    return {"scope": "VN", "retrieved_at": retrieved, "reports": reports, "comtrade_2026_ytd": ytd, "comtrade_full_api": full_api, "hs6_product_mapping": HS6_PRODUCT_MAP, "national_profiles": profiles, "current_indicator_inventory": [
        {"indicator": "34-unit provincial socioeconomic context", "source": "NSO Statistical Yearbook 2025 · 34-province appendix", "status": "official source identified; appendix extraction is a separate refresh and must not be substituted for IIP", "geography": "34 current provinces", "source_url": "https://www.nso.gov.vn/default/2026/07/nien-giam-thong-ke-2025/"},
        {"indicator": "IIP/manufacturing growth", "source": "NSO Industry E07.01/E07.02", "taxonomy_version": "VSIC2018 where the table exposes industry labels", "status": "available through preliminary 2024; 2025–2026 not in current catalog snapshot", "geography": "national and province"},
        {"indicator": "new enterprises", "source": "NSO Enterprise E05.01/E05.02", "status": "available in national/province snapshots", "geography": "national and province"},
        {"indicator": "acting enterprises with outcomes", "source": "NSO Enterprise E05.07/E05.08", "status": "available in national/province snapshots", "geography": "national and province"},
        {"indicator": "returning enterprises", "source": "NSO statistical releases", "status": "not found in current machine-readable snapshot", "geography": "unknown"}
    ], "limitations": ["PX-Web publishes industry and province tables separately; no industry×province allocation was performed.", "Comtrade national imports are national context and are not assigned to provinces.", "Comtrade preview returned no rows for 2024-2025; this is recorded as no_rows_returned, never as zero imports.", "The authenticated Comtrade full endpoint requires a subscription key.", "NSO tables expose activity labels but not a complete VSIC code dimension in this snapshot."]}


def main() -> None:
    """Parse refresh options, build the manifest, and publish it to disk."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("data/market/vietnam_foundation"))
    parser.add_argument("--years", default="2021,2022,2023,2024,2025")
    args = parser.parse_args()
    retrieved = datetime.now(timezone.utc).isoformat()
    manifest = _build_manifest(args.output, [int(item) for item in args.years.split(",")], retrieved)
    (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(manifest, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
