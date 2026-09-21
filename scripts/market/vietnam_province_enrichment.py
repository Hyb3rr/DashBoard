"""Collect province-level FDI and industrial-park context without scoring.

The collector keeps source geography and source periods intact. It only
normalizes names to the 34-unit catalogue; it never reallocates historical
ratios or infers missing park statistics.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import tempfile
import urllib.request
from io import BytesIO
from datetime import datetime, timezone
from pathlib import Path

from app.core.vietnam_geography import PROVINCES

_ROOT = Path(__file__).resolve().parents[2]
_CROSSWALK = json.loads((_ROOT / "schemas/vietnam_province_crosswalk.json").read_text(encoding="utf-8"))
_OLD_NAME_TO_CODE = {
    row["old_name"]: row["new_code"]
    for row in _CROSSWALK["entries"]
    if row["old_code"] == row["new_code"]
    and row.get("relation") in {"unchanged", "renamed"}
    and row.get("aggregation") == "identity"
}
_CODE_TO_NAME = {row["code"]: row["name"] for row in PROVINCES}


FDI_SOURCES = {
    "2025": "https://fdi.mof.gov.vn/Pages/chitiettin.aspx?idTin=185&idcm=9",
    "2026-07": "https://fdi.mof.gov.vn/Pages/chitiettin.aspx?idTin=2211&idcm=9",
}
FDI_STOCK_REPORT_SOURCE = "https://fia.mof.gov.vn/Detail/CatID/5102536e-ffed-4c97-83c9-24788f5e7d0c/NewsID/cd350403-11b2-4f81-b68c-c33e08160d5c"
FDI_STOCK_ATTACHMENT_URL = "https://fia.mof.gov.vn/Portals/0/Upload/3/NewsAttach/2026/8/12/Copy%20of%20FDI%2007.2026%20(F).pdf"
NSO_IP_PRESENCE_SOURCE = "https://www.nso.gov.vn/wp-content/uploads/2025/12/2.-BAO-CAO-SO-BO-TDTNN-2025_FINAL.pdf"
KCN_DIRECTORY = "https://investvietnam.gov.vn/en/industrial-zones.pl.html"
HUNG_YEN_KCN_SOURCE = "https://banqlkcn.hungyen.gov.vn/en-us/list-of-industrial-parks-in-operation-c2202.html"
OFFICIAL_PROVINCE_KCN_SOURCES = {
    # These pages are official investment/authority publications. Values are
    # accepted only when the page states a current-period province context.
    "37": {
        "province_name": "Ninh Bình",
        "url": "https://investvietnam.gov.vn/vi/tin-tuc.nd/ninh-binh-hoan-thien-ha-tang-san-sang-don-nhan-lan-song-dau-tu-moi.html",
        "source_name": "InvestVietnam / Ninh Bình provincial industrial-park report",
        "reference_period": "2025-08",
        "boundary_basis": "article describes Ninh Bình province after the 2025 administrative change; preserve source wording",
    },
    "79": {
        "province_name": "Hồ Chí Minh",
        "url": "https://investvietnam.gov.vn/vi/dia-phuong.td/thanh-pho-ho-chi-minh.html",
        "source_name": "InvestVietnam / Hồ Chí Minh provincial investment profile",
        "reference_period": "source-page-current-legacy",
        "boundary_basis": "legacy profile; do not use for current 2025 boundary comparison until revalidated",
    },
}
FDI_ALIASES = {
    "TP. Hồ Chí Minh": "Hồ Chí Minh", "Hồ Chí Minh": "Hồ Chí Minh",
    "TP Hồ Chí Minh": "Hồ Chí Minh", "Hà Nội": "Hà Nội",
}
FDI_ALIASES.update({"TP. Hà Nội": "Hà Nội", "Thành phố Hồ Chí Minh": "Hồ Chí Minh"})


def _request(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "IPIntel-VN-Province-Context/1.0"})
    with urllib.request.urlopen(req, timeout=90) as response:
        return response.read()


def _number(value: object) -> float | None:
    text = "" if value is None else str(value).strip()
    if not text or text.lower() in {"nan", "none", "-", "–", "—"}:
        return None
    negative = text.startswith("-") or "↓" in text or "decrease" in text.lower()
    match = re.search(r"\d[\d.,]*", text)
    if not match:
        return None
    number = match.group(0)
    # FIA uses English thousands separators in current reports and Vietnamese
    # decimal commas in older tables. Infer the decimal mark from the suffix.
    if "." in number and "," in number:
        if number.rfind(".") > number.rfind(","):
            number = number.replace(",", "")
        else:
            number = number.replace(".", "").replace(",", ".")
    elif number.count(",") == 1 and len(number.rsplit(",", 1)[1]) <= 2:
        number = number.replace(",", ".")
    elif number.count(".") == 1 and len(number.rsplit(".", 1)[1]) <= 2:
        number = number
    else:
        number = number.replace(",", "").replace(".", "")
    try:
        parsed = float(number)
    except ValueError:
        return None
    return -parsed if negative else parsed


def _province_name(value: object) -> str:
    text = html.unescape(str(value or "")).strip()
    return FDI_ALIASES.get(text, text)


def parse_fdi_html(raw: bytes, source_url: str, reference_period: str, retrieved_at: str) -> list[dict]:
    """Parse FIA's province ranking table when present.

    FIA publishes a ranking table rather than a complete 34-province panel;
    records absent from that table remain null in the output.
    """
    try:
        import pandas as pd
        tables = pd.read_html(raw)
    except Exception:
        tables = []
    rows_by_code: dict[str, dict] = {}
    for table in tables:
        if table.shape[1] < 3:
            continue
        column_headers = [str(x) for x in table.columns.tolist()]
        first_row = [str(x) for x in table.iloc[0].tolist()]
        has_real_headers = any("Địa phương" in x for x in column_headers)
        if not has_real_headers and not any("Địa phương" in x for x in first_row):
            continue
        data_rows = table.itertuples(index=False, name=None) if has_real_headers else table.iloc[1:].itertuples(index=False, name=None)
        for values in data_rows:
            name = _province_name(values[1] if len(values) > 1 else "")
            if not name or name.lower() == "nan":
                continue
            target_code = next((u["code"] for u in PROVINCES if u["name"] == name), None)
            if target_code is None:
                old_code = _OLD_NAME_TO_CODE.get(name)
                target_code = old_code
            if not target_code:
                continue
            current = rows_by_code.setdefault(target_code, {"source_names": [], "total": None, "yoy_values": [], "raw_rows": []})
            amount = _number(values[2] if len(values) > 2 else None)
            if amount is not None:
                current["total"] = (current["total"] or 0.0) + amount
            yoy = _number(values[3] if len(values) > 3 else None)
            if yoy is not None:
                current["yoy_values"].append(yoy)
            current["source_names"].append(name)
            current["raw_rows"].append([str(v) for v in values])
        break

    records = []
    for unit in PROVINCES:
        parsed = rows_by_code.get(unit["code"], {})
        present = bool(parsed)
        limitation = None if present else "FIA report publishes a provincial ranking subset; no row was published for this 34-unit province in the parsed table."
        records.append({
            "geo_unit_id": unit["code"],
            "province_name": unit["name"],
            "source_geography": parsed.get("source_names") if present else None,
            "reference_period": reference_period,
            "total_registered_fdi_usd_million": parsed.get("total"),
            "new_project_capital_usd_million": None,
            "adjusted_capital_usd_million": None,
            "project_count": None,
            "yoy_pct": parsed.get("yoy_values", [None])[0] if len(parsed.get("yoy_values", [])) == 1 else None,
            "manufacturing_fdi_usd_million": None,
            "source_name": "Foreign Investment Agency / Ministry of Finance FDI report",
            "source_url": source_url,
            "retrieved_at": retrieved_at,
            "geography_basis": "FIA reported province ranking; normalized to 34-unit catalogue by exact/alias name",
            "unit": "USD million",
            "raw_value": parsed.get("raw_rows"),
            "transformation_method": "numeric parsing; additive total only across legacy names mapped to one 2025 unit; ratios are not aggregated",
            "confidence": "high" if present else "missing",
            "limitation": limitation or "The report does not provide province-level new/adjusted/project-count fields in the parsed table; manufacturing breakdown is not available at province level.",
        })
    return records


def _stock_rows(raw: bytes):
    """Read an FIA Appendix III attachment without assuming its file type."""
    import pandas as pd
    tables = []
    try:
        tables.extend(pd.read_html(raw))
    except (ImportError, ValueError):
        pass
    if not tables:
        try:
            tables.extend(pd.read_excel(BytesIO(raw), sheet_name=None, header=None).values())
        except (ImportError, ValueError, OSError):
            pass
    return tables


def parse_fdi_stock_attachment(raw: bytes, source_url: str, reference_period: str, retrieved_at: str) -> list[dict]:
    """Parse a complete FIA cumulative-stock table.

    A stock snapshot is publishable only when every current 34-unit province
    appears exactly once. Summary rows or a top-10 table are rejected rather
    than being treated as zero or allocated to the omitted provinces.
    """
    rows_by_code = {}
    for table in _stock_rows(raw):
        if getattr(table, "shape", (0, 0))[1] < 3:
            continue
        for values in table.itertuples(index=False, name=None):
            cells = [str(value).strip() for value in values]
            name = next((_province_name(value) for value in cells if _province_name(value) in {u["name"] for u in PROVINCES}), None)
            if not name:
                continue
            code = next(u["code"] for u in PROVINCES if u["name"] == name)
            numeric = [_number(value) for value in cells]
            numeric = [value for value in numeric if value is not None]
            if not numeric:
                continue
            if code in rows_by_code:
                raise ValueError(f"duplicate province in FIA stock attachment: {name}")
            rows_by_code[code] = {"name": name, "raw": cells, "stock": numeric[-1]}
        if rows_by_code:
            break
    if len(rows_by_code) != len(PROVINCES):
        raise ValueError(f"incomplete FIA stock attachment: {len(rows_by_code)}/{len(PROVINCES)} provinces")
    return [{
        "geo_unit_id": unit["code"], "province_name": unit["name"],
        "source_geography": rows_by_code[unit["code"]]["name"],
        "reference_period": reference_period,
        "fdi_stock_cumulative_usd_million": rows_by_code[unit["code"]]["stock"],
        "fdi_implemented_cumulative_usd_million": None, "active_project_count": None,
        "source_name": "Foreign Investment Agency / Ministry of Finance FIA Appendix III",
        "source_url": source_url, "retrieved_at": retrieved_at,
        "geography_basis": "FIA Appendix III province row; exact current 34-unit geography",
        "unit": "USD million", "raw_value": rows_by_code[unit["code"]]["raw"],
        "transformation_method": "numeric parsing only; no allocation of summary rows",
        "confidence": "high", "limitation": "Appendix table does not provide a province manufacturing breakdown in this field.",
    } for unit in PROVINCES]


def parse_fdi_stock_pdf_text(text: str, source_url: str, retrieved_at: str) -> list[dict]:
    """Parse FIA Appendix III text extracted from the official PDF."""
    aliases = {"TP. Hồ Chí Minh": "Hồ Chí Minh", "Đăk Lăk": "Đắk Lắk"}
    by_name = {u["name"]: u for u in PROVINCES}
    rows = {}
    excluded_nonprovince_stock = None
    in_locality_table = False
    for raw_line in text.splitlines():
        line = " ".join(raw_line.split())
        if "STT Địa Phương" in line:
            in_locality_table = True
            continue
        if not in_locality_table or line.startswith("Tổng"):
            continue
        if "Dầu khí" in line:
            match = re.search(r"\s(\d[\d.,]*)\s+[\d.,]+%$", line)
            excluded_nonprovince_stock = _number(match.group(1)) if match else None
            continue
        match = re.match(r"^\d+\s+(.+?)\s+(\d[\d.,]*)\s+(\d[\d.,]*)\s+[\d.,]+%$", line)
        if not match:
            continue
        name = aliases.get(match.group(1), match.group(1))
        if name not in by_name:
            continue
        if name in rows:
            raise ValueError(f"duplicate FIA stock province: {name}")
        rows[name] = {"projects": _number(match.group(2)), "stock": _number(match.group(3)), "raw": line}
    if set(rows) != set(by_name):
        raise ValueError(f"incomplete FIA Appendix III province rows: {len(rows)}/{len(by_name)}")
    total = sum(value["stock"] for value in rows.values())
    anchors = {"Hồ Chí Minh": 149050.87, "Bắc Ninh": 51469.26, "Hải Phòng": 47848.92}
    for name, expected in anchors.items():
        if abs(rows[name]["stock"] - expected) > 0.01:
            raise ValueError(f"FIA stock anchor mismatch: {name}")
    if excluded_nonprovince_stock is None or abs(total + excluded_nonprovince_stock - 559238.87) > 1.0:
        raise ValueError(f"FIA stock total mismatch: provinces={total}, excluded={excluded_nonprovince_stock}")
    return [{
        "geo_unit_id": unit["code"], "province_name": unit["name"], "source_geography": unit["name"],
        "reference_period": "cumulative_to_2026-07-31", "fdi_stock_cumulative_usd_million": rows[unit["name"]]["stock"],
        "fdi_implemented_cumulative_usd_million": None, "active_project_count": int(rows[unit["name"]]["projects"]),
        "source_name": "Foreign Investment Agency / Ministry of Finance FIA Appendix III",
        "source_url": source_url, "retrieved_at": retrieved_at,
        "geography_basis": "FIA Appendix III province row; current 34-unit geography",
        "unit": "USD million", "raw_value": rows[unit["name"]]["raw"],
        "transformation_method": "PDF text extraction; numeric parsing; excluded non-province Dầu khí row; anchor and national-total validation",
        "confidence": "high", "limitation": "Cumulative stock is all-sector FDI; the attachment does not provide province-level manufacturing stock.",
    } for unit in PROVINCES]


def build_unavailable_fdi_stock(retrieved_at: str) -> dict:
    return {"records": [{
        "geo_unit_id": unit["code"], "province_name": unit["name"],
        "source_geography": None, "reference_period": "cumulative_to_2026-07-31",
        "fdi_stock_cumulative_usd_million": None, "fdi_implemented_cumulative_usd_million": None,
        "active_project_count": None, "source_name": "Foreign Investment Agency / Ministry of Finance FIA Appendix III",
        "source_url": FDI_STOCK_REPORT_SOURCE, "retrieved_at": retrieved_at,
        "geography_basis": "current 34-unit catalogue; attachment not ingested",
        "unit": "USD million", "raw_value": None, "transformation_method": "none",
        "confidence": "missing", "limitation": "Official FIA report states Appendix III contains all 34 province rows, but the attachment was not available to the refresh; no value was inferred from the HTML top-10 table.",
        "status": "not_ingested",
    } for unit in PROVINCES], "fetch_status": "attachment_not_ingested", "source_url": FDI_STOCK_REPORT_SOURCE}


def parse_industrial_presence_attachment(raw: bytes, source_url: str, retrieved_at: str) -> list[dict]:
    """Parse NSO's current-34 table of communes with industrial parks."""
    rows = {}
    for table in _stock_rows(raw):
        for values in table.itertuples(index=False, name=None):
            cells = [str(v).strip() for v in values]
            name = next((_province_name(v) for v in cells if _province_name(v) in {u["name"] for u in PROVINCES}), None)
            if not name:
                continue
            code = next(u["code"] for u in PROVINCES if u["name"] == name)
            nums = [_number(v) for v in cells]
            nums = [v for v in nums if v is not None]
            if len(nums) < 2:
                continue
            if code in rows:
                raise ValueError(f"duplicate province in NSO industrial-presence table: {name}")
            rows[code] = (nums[-3], nums[-2], nums[-1], cells)
        if rows:
            break
    if len(rows) != len(PROVINCES):
        raise ValueError(f"incomplete NSO industrial-presence table: {len(rows)}/{len(PROVINCES)} provinces")
    return [{
        "geo_unit_id": unit["code"], "province_name": unit["name"],
        "reference_period": "2025-07-01", "communes_total": rows[unit["code"]][0], "communes_with_industrial_park": rows[unit["code"]][1],
        "commune_ip_presence_rate_pct": rows[unit["code"]][2],
        "source_name": "NSO 2025 Rural and Agriculture Census", "source_url": source_url,
        "retrieved_at": retrieved_at, "source_geography": rows[unit["code"]][2][0],
        "geography_basis": "NSO table reported on current 34-unit geography",
        "unit": "communes; %", "raw_value": rows[unit["code"]][3],
        "transformation_method": "numeric parsing only", "confidence": "high",
        "limitation": "Commune presence is an infrastructure proxy; it is not an industrial-park count or area.",
    } for unit in PROVINCES]


def validate_industrial_presence_records(records: list[dict], *, expected_total: int = 401, expected_rate: float = 15.23) -> dict:
    """Validate final NSO Table 23 before publication."""
    if len(records) != len(PROVINCES) or len({row.get("geo_unit_id") for row in records}) != len(PROVINCES):
        raise ValueError("NSO Table 23 must contain exactly 34 unique current provinces")
    for row in records:
        total = row.get("communes_total")
        count = row.get("communes_with_industrial_park")
        rate = row.get("commune_ip_presence_rate_pct")
        if count is None:
            continue
        if count < 0 or (total is not None and (total < 0 or count > total)):
            raise ValueError(f"impossible NSO industrial-presence row: {row.get('province_name')}")
        if rate is not None and total:
            calculated = count / total * 100
            if abs(calculated - rate) > 0.15:
                raise ValueError(f"rate mismatch in NSO industrial-presence row: {row.get('province_name')}")
    total_count = sum(row.get("communes_with_industrial_park") or 0 for row in records)
    if total_count != expected_total:
        raise ValueError(f"NSO Table 23 national industrial-presence total {total_count} != {expected_total}")
    total_communes = sum(row.get("communes_total") or 0 for row in records)
    rate = total_count / total_communes * 100 if total_communes else 0
    if abs(rate - expected_rate) > 0.15:
        raise ValueError(f"NSO Table 23 national rate {rate:.2f} != {expected_rate:.2f}")
    return {"province_rows": len(records), "communes_with_industrial_park": total_count, "communes_total": total_communes, "national_rate_pct": round(rate, 2), "source_status": "official_final"}


def build_unavailable_industrial_presence(retrieved_at: str) -> dict:
    return {"records": [{
        "geo_unit_id": unit["code"], "province_name": unit["name"],
        "reference_period": "2025-07-01", "communes_with_industrial_park": None,
        "commune_ip_presence_rate_pct": None, "source_name": "NSO 2025 Rural and Agriculture Census",
        "source_url": NSO_IP_PRESENCE_SOURCE, "retrieved_at": retrieved_at,
        "source_geography": None, "geography_basis": "current 34-unit catalogue; attachment not ingested",
        "unit": "communes; %", "raw_value": None, "transformation_method": "none",
        "confidence": "missing", "limitation": "Official NSO final Table 23 was located but failed source-integrity checks because rendered values lose zero digits; preliminary values are not used.",
        "status": "rejected_source_integrity", "value_status": "unavailable",
    } for unit in PROVINCES], "fetch_status": "rejected_source_integrity", "source_url": NSO_IP_PRESENCE_SOURCE,
    "limitation": "Official NSO final Table 23 was located and audited, but rendered values fail consistency checks (including dropped zero digits); preliminary values are not used."}


def build_kcn_context(retrieved_at: str) -> list[dict]:
    records = []
    for unit in PROVINCES:
        records.append({
            "geo_unit_id": unit["code"],
            "province_name": unit["name"],
            "reference_period": None,
            "industrial_park_count": None,
            "operating_industrial_park_count": None,
            "total_area_ha": None,
            "industrial_service_land_ha": None,
            "leased_land_ha": None,
            "occupancy_rate_pct": None,
            "infrastructure_investment": None,
            "tenant_count": None,
            "source_name": "InvestVietnam industrial-zone directory",
            "source_url": KCN_DIRECTORY,
            "retrieved_at": retrieved_at,
            "geography_basis": "province-level value not published as a structured aggregate in the directory",
            "unit": None,
            "raw_value": None,
            "transformation_method": "none",
            "confidence": "missing",
            "limitation": "Official directory lists individual zones but does not provide a validated 34-province aggregate for this field; no count or ratio was inferred.",
        })
    return records


def parse_hung_yen_kcn_html(raw: bytes, retrieved_at: str) -> dict:
    text = re.sub(r"<[^>]+>", " ", html.unescape(raw.decode("utf-8", errors="ignore")))
    text = re.sub(r"\s+", " ", text)
    areas = [_number(value) for value in re.findall(r"Total area\s*:\s*([0-9.,]+)", text, flags=re.I)]
    areas = [value for value in areas if value is not None]
    # The authority page currently renders the same bilingual list twice.
    # Remove an exact repeated block; do not deduplicate equal area values,
    # because two different parks can legitimately have the same area.
    if len(areas) % 2 == 0 and areas[: len(areas) // 2] == areas[len(areas) // 2 :]:
        areas = areas[: len(areas) // 2]
    return {
        "geo_unit_id": "33", "province_name": "Hưng Yên", "reference_period": "page-current",
        "industrial_park_count": len(areas), "operating_industrial_park_count": len(areas),
        "total_area_ha": sum(areas) if areas else None, "industrial_service_land_ha": None,
        "leased_land_ha": None, "occupancy_rate_pct": None, "infrastructure_investment": None,
        "tenant_count": None, "source_name": "Hưng Yên Industrial Parks Management Board",
        "source_url": HUNG_YEN_KCN_SOURCE, "retrieved_at": retrieved_at,
        "geography_basis": "official provincial management-board list of industrial parks in operation",
        "unit": "count; ha", "raw_value": {"total_area_values_ha": areas},
        "transformation_method": "counted listed area entries; summed area only; no ratios inferred",
        "confidence": "medium", "limitation": "The page publishes park names and total area but no occupancy, leased land, tenant count, service land, or investment totals."
    }


def parse_investvietnam_kcn_html(raw: bytes, source: dict, retrieved_at: str) -> dict:
    """Parse explicitly published province KCN context from an official page.

    This parser accepts only explicit counts/areas/occupancy in the page text;
    it never counts directory cards or treats a planning target as operating.
    """
    text = re.sub(r"<[^>]+>", " ", html.unescape(raw.decode("utf-8", errors="ignore")))
    text = re.sub(r"\s+", " ", text)
    count_match = re.search(r"(\d+)\s+khu công nghiệp\s+đang hoạt động", text, flags=re.I)
    area_match = re.search(r"(?:diện tích đất công nghiệp đã cho thuê|tổng diện tích.{0,80}?)\s*(?:đạt|là)?\s*([0-9][0-9.,]*)\s*ha", text, flags=re.I)
    occupancy_match = re.search(r"lấp đầy bình quân[^0-9]{0,40}([0-9.,]+)\s*%", text, flags=re.I)
    count = int(count_match.group(1)) if count_match else None
    area = _number(area_match.group(1)) if area_match else None
    occupancy = _number(occupancy_match.group(1)) if occupancy_match else None
    return {
        "geo_unit_id": next((code for code, item in _CODE_TO_NAME.items() if item == source["province_name"]), None),
        "province_name": source["province_name"], "reference_period": source["reference_period"],
        "industrial_park_count": count, "operating_industrial_park_count": count,
        "total_area_ha": None, "industrial_service_land_ha": None,
        "leased_land_ha": area, "occupancy_rate_pct": occupancy,
        "infrastructure_investment": None, "tenant_count": None,
        "source_name": source["source_name"], "source_url": source["url"],
        "retrieved_at": retrieved_at, "geography_basis": source["boundary_basis"],
        "unit": "count; ha; %", "raw_value": {"count": count, "leased_land_ha": area, "occupancy_rate_pct": occupancy},
        "transformation_method": "parsed explicit page statements; no planning target or directory card counted",
        "confidence": "medium" if count is not None else "missing",
        "limitation": "Page does not publish all requested KCN fields; source boundary wording must be reviewed before cross-province comparison."
    }


def coverage_gate(records: list[dict], fields: tuple[str, ...], threshold: int = 20) -> dict:
    coverage = {field: sum(row.get(field) is not None for row in records) for field in fields}
    return {"coverage": coverage, "threshold": threshold, "eligible_for_province_comparison": {field: count >= threshold for field, count in coverage.items()}, "ranking_enabled": False}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("data/market/vietnam_province_enrichment"))
    parser.add_argument("--skip-network", action="store_true")
    parser.add_argument("--fdi-stock-source", type=Path, help="local FIA Appendix III attachment (HTML/XLS/XLSX)")
    parser.add_argument("--industrial-presence-source", type=Path, help="local NSO industrial-presence attachment (HTML/XLS/XLSX)")
    args = parser.parse_args()
    if args.skip_network:
        print(json.dumps({"status": "skipped", "published": False}, ensure_ascii=False))
        return
    retrieved_at = datetime.now(timezone.utc).isoformat()
    fdi_records = []
    fetch_status = {}
    refresh_ok = True
    for period, url in FDI_SOURCES.items():
        try:
            fdi_records.extend(parse_fdi_html(_request(url), url, period, retrieved_at))
            fetch_status[period] = "loaded"
        except Exception as exc:
            fetch_status[period] = {"status": "failed", "error": type(exc).__name__}
            refresh_ok = False
    # Keep the last complete snapshot when any source in this batch fails.
    output = args.output
    output.mkdir(parents=True, exist_ok=True)
    kcn_records = build_kcn_context(retrieved_at)
    stock_payload = build_unavailable_fdi_stock(retrieved_at)
    presence_payload = build_unavailable_industrial_presence(retrieved_at)
    if args.fdi_stock_source:
        stock_bytes = args.fdi_stock_source.read_bytes()
        if args.fdi_stock_source.suffix.lower() == ".pdf":
            try:
                from pypdf import PdfReader
                stock_text = "\n".join((page.extract_text() or "") for page in PdfReader(BytesIO(stock_bytes)).pages)
            except ImportError as exc:
                raise RuntimeError("PDF stock ingestion requires pypdf in the refresh environment") from exc
            stock_records = parse_fdi_stock_pdf_text(stock_text, FDI_STOCK_ATTACHMENT_URL, retrieved_at)
        else:
            stock_records = parse_fdi_stock_attachment(stock_bytes, FDI_STOCK_ATTACHMENT_URL, "cumulative_to_2026-07-31", retrieved_at)
        stock_payload = {"records": stock_records, "fetch_status": "loaded_complete", "source_url": FDI_STOCK_REPORT_SOURCE}
    if args.industrial_presence_source:
        presence_payload = {"records": parse_industrial_presence_attachment(args.industrial_presence_source.read_bytes(), NSO_IP_PRESENCE_SOURCE, retrieved_at), "fetch_status": "loaded_complete", "source_url": NSO_IP_PRESENCE_SOURCE}
    try:
        kcn_records = [parse_hung_yen_kcn_html(_request(HUNG_YEN_KCN_SOURCE), retrieved_at) if row["geo_unit_id"] == "33" else row for row in kcn_records]
        for code, source in OFFICIAL_PROVINCE_KCN_SOURCES.items():
            if code == "79":
                continue
            parsed = parse_investvietnam_kcn_html(_request(source["url"]), source, retrieved_at)
            kcn_records = [parsed if row["geo_unit_id"] == code else row for row in kcn_records]
    except Exception as exc:
        fetch_status["kcn"] = {"status": "failed", "error": type(exc).__name__}
        refresh_ok = False

    if refresh_ok:
        payloads = {
            output / "province_fdi_context.json": {"records": fdi_records, "fetch_status": fetch_status},
            output / "province_fdi_stock_context.json": stock_payload,
            output / "province_industrial_presence_context.json": presence_payload,
            output / "province_industrial_park_context.json": {"records": kcn_records, "coverage_gate": coverage_gate(kcn_records, ("industrial_park_count", "operating_industrial_park_count", "total_area_ha", "occupancy_rate_pct", "tenant_count", "leased_land_ha"))},
        }
        for path, payload in payloads.items():
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
                json.dump(payload, handle, ensure_ascii=False, indent=2)
                temp_path = handle.name
            os.replace(temp_path, path)
    print(json.dumps({"fdi_records": len(fdi_records), "kcn_records": len(PROVINCES), "fetch_status": fetch_status, "published": refresh_ok}, ensure_ascii=False))


if __name__ == "__main__":
    main()
