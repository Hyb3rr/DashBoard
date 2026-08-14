"""Download and safely replace local World Bank WDI input data."""

from __future__ import annotations

import argparse
import csv
import io
import json
import math
import os
import tempfile
from pathlib import Path
from urllib.request import Request, urlopen

from ..config.settings import DATA_DIR
from .market_refresh import WB_CODES, WB_LABELS

WB_DATA = DATA_DIR / "worldbank" / "Data.csv"
WB_API = "https://api.worldbank.org/v2/country/all/indicator/{indicator}?format=json&per_page=30000"
YEARS = tuple(range(2016, 2026))


def _fetch(indicator: str, timeout: float = 30.0) -> list[dict]:
    request = Request(WB_API.format(indicator=indicator), headers={"User-Agent": "SentinelHub-WDI/1.0"})
    with urlopen(request, timeout=timeout) as response:
        payload = response.read()
    decoded = json.loads(payload.decode("utf-8-sig"))
    if not isinstance(decoded, list) or len(decoded) < 2 or not isinstance(decoded[1], list):
        raise ValueError("malformed World Bank response")
    return decoded[1]


def _validate(raw: dict[str, list[dict]], min_country_count: int = 50) -> list[str]:
    required = set(WB_CODES.values())
    if set(raw) != required or any(not records for records in raw.values()):
        raise ValueError("required indicator response missing or empty")
    countries = set()
    for records in raw.values():
        for record in records:
            iso3 = str(record.get("countryiso3code") or "").upper()
            try:
                value = float(record["value"])
                year = int(record["date"])
            except (KeyError, TypeError, ValueError):
                continue
            if iso3 and 2016 <= year <= 2025 and math.isfinite(value):
                countries.add(iso3)
    if len(countries) < min_country_count:
        raise ValueError("World Bank country coverage too small")
    return sorted(countries)


def _csv_bytes(raw: dict[str, list[dict]], countries: list[str]) -> bytes:
    names = {value: key for key, value in WB_CODES.items()}
    rows = {}
    for code, records in raw.items():
        for record in records:
            iso3 = str(record.get("countryiso3code") or "").upper()
            year = int(record.get("date") or 0)
            if iso3 not in countries or year not in YEARS:
                continue
            key = (iso3, code)
            rows.setdefault(key, {"name": (record.get("country") or {}).get("value", iso3), "values": {}})
            rows[key]["values"][year] = ".." if record.get("value") is None else str(record["value"])
    output = io.StringIO()
    fields = ["Country Name", "Country Code", "Series Name", "Series Code"] + [f"{year} [YR{year}]" for year in YEARS]
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    for (iso3, code), item in sorted(rows.items()):
        row = {"Country Name": item["name"], "Country Code": iso3, "Series Name": WB_LABELS.get(names[code], code), "Series Code": code}
        row.update({f"{year} [YR{year}]": item["values"].get(year, "..") for year in YEARS})
        writer.writerow(row)
    return output.getvalue().encode("utf-8")


def _atomic(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def update_world_bank(data_path: str | Path = WB_DATA, timeout: float = 30.0,
                      min_country_count: int = 50, refresh_market: bool = True) -> dict:
    data_path = Path(data_path)
    raw = {}
    try:
        for code in WB_CODES.values():
            raw[code] = _fetch(code, timeout)
        countries = _validate(raw, min_country_count)
        content = _csv_bytes(raw, countries)
        if not content.strip():
            raise ValueError("empty World Bank CSV")
        if data_path.exists() and data_path.read_bytes() == content:
            return {"status": "not_modified", "changed": False, "countries": len(countries)}
        if data_path.exists():
            _atomic(data_path.with_name("Data.last-good.csv"), data_path.read_bytes())
        _atomic(data_path, content)
        _atomic(data_path.with_name("Data.raw.json"), json.dumps(raw, ensure_ascii=False).encode("utf-8"))
        result = {"status": "updated", "changed": True, "countries": len(countries), "indicators": len(raw)}
        if refresh_market:
            from .market_refresh import refresh
            result["market_refresh"] = refresh()
        return result
    except Exception as exc:
        return {"status": "failed", "changed": False, "error": type(exc).__name__, "message": str(exc)}


def main() -> int:
    parser = argparse.ArgumentParser(description="Refresh local World Bank WDI data")
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()
    result = update_world_bank(timeout=args.timeout)
    print(json.dumps(result, indent=2, default=str))
    return 0 if result["status"] in {"updated", "not_modified"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
