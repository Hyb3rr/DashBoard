"""Refresh current Vietnam province indicators from NQ 262 Table 2.

The refresh is batch-only.  It keeps numeric values, reported dashes and
source/period metadata separate; a dash is never converted to zero.
"""
from __future__ import annotations

import argparse
import html
import json
import re
import sys
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from app.core.vietnam_geography import PROVINCES

DEFAULT_OUTPUT = ROOT / "data/market/vietnam_province_enrichment/province_current_indicators.json"
SOURCE_URL = "https://vanban.chinhphu.vn/?docid=219376&orggroupid=2&pageid=27160"
REFERENCE_PERIOD = "2026-01..2026-08"

# Official Table 2 is also mirrored as HTML by a legal-information publisher.
# These rows are a checked snapshot of that table, retained so a refresh can
# be reproduced even when the official PDF is temporarily unavailable.
SEED_ROWS = (
    ("TP. Hồ Chí Minh", "23,3", "10,6", "10.469,35"), ("Hà Nội", "12,4", "8,9", "3.751,75"),
    ("Hải Phòng", "5,7", "15,2", "3.053,99"), ("Đồng Nai", "5,3", "12,2", "1.289,35"),
    ("Bắc Ninh", "4,1", "20,2", "3.481,11"), ("Phú Thọ", "3,2", "21,7", "1.010,31"),
    ("Quảng Ninh", "2,9", "16,2", "667,60"), ("Lâm Đồng", "2,8", "10,6", "26,89"),
    ("Tây Ninh", "2,7", "15,0", "1.579,14"), ("Ninh Bình", "2,7", "25,7", "1.369,87"),
    ("Thanh Hóa", "2,6", "11,1", "288,29"), ("Hưng Yên", "2,5", "15,8", "749,65"),
    ("Đà Nẵng", "2,5", "9,7", "426,75"), ("Cần Thơ", "2,4", "10,0", "89,48"),
    ("An Giang", "2,3", "13,8", "17,78"), ("Đồng Tháp", "2,2", "12,6", "173,8"),
    ("Vĩnh Long", "2,2", "9,5", "110,26"), ("Gia Lai", "2,1", "7,8", "180,52"),
    ("Nghệ An", "1,9", "21,1", "2.385,3"), ("Đắk Lắk", "1,8", "14,6", "2,89"),
    ("Khánh Hòa", "1,6", "7,8", "39,72"), ("Thái Nguyên", "1,5", "22,2", "8.066,17"),
    ("Quảng Ngãi", "1,5", "14,2", "39,81"), ("Cà Mau", "1,3", "12,5", "99,45"),
    ("Lào Cai", "1,1", "6,5", "-24,56"), ("Quảng Trị", "1,0", "12,2", "173,78"),
    ("Hà Tĩnh", "0,9", "38,9", "412,6"), ("Sơn La", "0,7", "10,1", "-"),
    ("Tuyên Quang", "0,7", "9,5", "16,02"), ("Huế", "0,7", "10,2", "-"),
    ("Lạng Sơn", "0,5", "7,6", "-"), ("Lai Châu", "0,3", "4,4", "-"),
    ("Điện Biên", "0,3", "12,0", "549,4"), ("Cao Bằng", "0,2", "12,2", "-"),
)


def _key(value: str) -> str:
    """Normalize a province label for alias-catalogue lookup."""
    value = str(value).replace("Đ", "D").replace("đ", "d")
    value = re.sub(r"[^a-z0-9]+", " ", value.lower())
    return " ".join(value.split())


ALIASES = {_key(unit["name"]): unit for unit in PROVINCES}
ALIASES.update({_key("TP. Hồ Chí Minh"): next(unit for unit in PROVINCES if unit["code"] == "79")})
ALIASES.update({_key("Tp Hồ Chí Minh"): next(unit for unit in PROVINCES if unit["code"] == "79")})
ALIASES.update({_key("Tp. Hồ Chí Minh"): next(unit for unit in PROVINCES if unit["code"] == "79")})


def _number(value: str | None) -> float | None:
    """Parse decimal-comma values while preserving reported dashes as missing."""
    if value is None:
        return None
    text = html.unescape(str(value)).strip().replace("%", "")
    if text in {"", "-", "–", "—", ".."}:
        return None
    text = text.replace(" ", "").replace(".", "").replace(",", ".")
    try:
        return float(text)
    except ValueError:
        return None


class _TableParser(HTMLParser):
    def __init__(self) -> None:
        """Initialize row and cell buffers for the lightweight HTML table parser."""
        super().__init__()
        self.rows: list[list[str]] = []
        self._row: list[str] | None = None
        self._cell: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Start buffering a table row or cell when its tag opens."""
        if tag == "tr":
            self._row = []
        elif tag in {"td", "th"} and self._row is not None:
            self._cell = []

    def handle_data(self, data: str) -> None:
        """Collect text content while a table cell is open."""
        if self._cell is not None:
            self._cell.append(data)

    def handle_endtag(self, tag: str) -> None:
        """Finalize buffered cells and append completed table rows."""
        if tag in {"td", "th"} and self._cell is not None and self._row is not None:
            self._row.append(" ".join("".join(self._cell).split()))
            self._cell = None
        elif tag == "tr" and self._row:
            self.rows.append(self._row)
            self._row = None


def parse_table_rows(rows: list[list[str]], source_url: str = SOURCE_URL, retrieved_at: str | None = None) -> list[dict]:
    """Map NQ 262 table rows into canonical province evidence records."""
    retrieved_at = retrieved_at or datetime.now(timezone.utc).isoformat()
    records = []
    for row in rows:
        if len(row) < 11 or not row[0].strip().isdigit():
            continue
        name = row[1].replace("Tp. ", "").strip()
        unit = ALIASES.get(_key(name))
        if not unit:
            continue
        # Table 2 columns: rank, province, GRDP share, IIP, IIP target,
        # IIP gap, retail, retail target, retail gap, CPI, FDI, FDI growth.
        fdi_raw = row[10].strip()
        fdi_value = _number(fdi_raw)
        records.append({
            "geo_unit_id": unit["code"], "province_name": unit["name"],
            "reference_period": REFERENCE_PERIOD, "iip_yoy_pct": _number(row[3]),
            "grdp_national_share_pct": _number(row[2]),
            "fdi_registered_period_usd_million": fdi_value,
            "fdi_status": "published" if fdi_value is not None else "reported_no_numeric_value",
            "source_name": "Government of Vietnam · NQ 262/NQ-CP · Appendix I Table 2",
            "source_url": source_url, "retrieved_at": retrieved_at,
            "source_geography": row[1], "geography_basis": "NQ 262 current 34-unit province table",
            "unit": {"iip_yoy_pct": "%", "grdp_national_share_pct": "%", "fdi_registered_period_usd_million": "USD million"},
            "raw_value": {"grdp_national_share_pct": row[2], "iip_yoy_pct": row[3], "fdi_registered_period_usd_million": fdi_raw},
            "transformation_method": "decimal-comma parsing; reported dash preserved as status, never converted to zero",
            "confidence": "high", "limitation": "FDI dash is reported by source without a numeric value; it is not interpreted as zero." if fdi_value is None else None,
        })
    return records


def parse_html_table(raw: str, source_url: str = SOURCE_URL) -> list[dict]:
    """Extract HTML table cells and parse them as current province records."""
    parser = _TableParser()
    parser.feed(raw)
    return parse_table_rows(parser.rows, source_url)


def _coverage(records: list[dict]) -> dict[str, int]:
    """Summarize observed province and numeric-field coverage."""
    return {
        "source_observations": len(records),
        "province_rows": len(records),
        "iip_numeric": sum(row["iip_yoy_pct"] is not None for row in records),
        "fdi_numeric": sum(row["fdi_status"] == "published" for row in records),
        "fdi_reported_without_numeric": sum(row["fdi_status"] == "reported_no_numeric_value" for row in records),
        "fdi_missing": sum(row["fdi_status"] not in {"published", "reported_no_numeric_value"} for row in records),
    }


def _snapshot_payload(records: list[dict], source_url: str, retrieved_at: str, source_basis: str) -> dict:
    """Build the shared VN snapshot envelope without changing record semantics."""
    return {
        "scope": "VN",
        "reference_period": REFERENCE_PERIOD,
        "source": {
            "source_name": "Government of Vietnam · NQ 262/NQ-CP · Appendix I Table 2",
            "source_url": source_url,
            "retrieved_at": retrieved_at,
            "source_basis": source_basis,
        },
        "records": records,
        "coverage": _coverage(records),
    }


def seed_snapshot(source_url: str = SOURCE_URL, retrieved_at: str | None = None) -> dict:
    """Build a reproducible snapshot from the checked 34-province transcription."""
    rows = [[str(i + 1), *row, "", "", "", "", "", "", ""] for i, row in enumerate(SEED_ROWS)]
    # Seed rows already contain the four source columns; pad to the table's FDI index.
    normalized = [[row[0], row[1], row[2], row[3], "", "", "", "", "", "", row[4], ""] for row in rows]
    records = parse_table_rows(normalized, source_url, retrieved_at)
    source_retrieved_at = retrieved_at or datetime.now(timezone.utc).isoformat()
    return _snapshot_payload(
        records,
        source_url,
        source_retrieved_at,
        "Checked transcription of the official 34-unit table; no OCR and no boundary aggregation",
    )


def _parse_source_file(source: Path) -> list[dict]:
    """Parse and validate one complete source file before snapshot publication."""
    if not source.exists():
        raise FileNotFoundError(source)
    raw = source.read_text(encoding="utf-8-sig")
    records = parse_html_table(raw, str(source)) if "<tr" in raw.lower() else []
    if len(records) != len(PROVINCES):
        raise ValueError(f"expected {len(PROVINCES)} current province rows, parsed {len(records)}; snapshot was not published")
    return records


def _write_snapshot(output: Path, payload: dict) -> None:
    """Create the output directory and write the complete JSON snapshot."""
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def refresh(source: Path | None, output: Path) -> dict:
    """Build and publish a complete current-indicator snapshot from source or seed."""
    retrieved_at = datetime.now(timezone.utc).isoformat()
    if source:
        records = _parse_source_file(source)
        payload = _snapshot_payload(
            records,
            str(source),
            retrieved_at,
            "Parsed HTML table; no OCR and no boundary aggregation",
        )
    else:
        payload = seed_snapshot(SOURCE_URL, retrieved_at)
    _write_snapshot(output, payload)
    return payload


def build_parser() -> argparse.ArgumentParser:
    """Build the source and output options for this offline refresh CLI."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser


def main() -> None:
    """Parse CLI options, refresh one snapshot, and print coverage diagnostics."""
    args = build_parser().parse_args()
    payload = refresh(args.source, args.output)
    print(json.dumps(payload["coverage"], ensure_ascii=False))


if __name__ == "__main__":
    main()
