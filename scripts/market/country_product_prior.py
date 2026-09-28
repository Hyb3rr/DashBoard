"""Build country x product prior snapshots from local Comtrade and WDI files."""

from __future__ import annotations

import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

import pycountry

from app.config.settings import DATA_DIR
from app.core.market_potential import country_prior_snapshot, minmax_normalize
from app.db.market_repository import MarketRepository
from scripts.market.country_sources import configured_signal, iso2


COMTRADE_DIR = DATA_DIR / "comtrade"
WORLD_BANK = DATA_DIR / "worldbank" / "Data.csv"
WDI_CODES = {"manufacturing_value_added": "NV.IND.MANF.CD", "manufacturing_growth": "NV.IND.MANF.KD.ZG"}


def _open_csv(path: Path):
    """Decode a CSV snapshot using supported encodings with replacement fallback."""
    raw = path.read_bytes()
    for encoding in ("utf-8-sig", "cp1252"):
        try:
            return raw.decode(encoding).splitlines()
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace").splitlines()


def _number(value: Any) -> float | None:
    """Parse a finite numeric value while treating malformed data as missing."""
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if number == number and abs(number) != float("inf") else None


_iso2 = iso2


def read_world_bank(path: Path = WORLD_BANK) -> dict[str, dict[str, float]]:
    """Read the latest available configured WDI value for each country."""
    result: dict[str, dict[str, float]] = defaultdict(dict)
    for row in csv.DictReader(_open_csv(path)):
        indicator = row.get("Series Code")
        name = next((key for key, code in WDI_CODES.items() if code == indicator), None)
        if not name:
            continue
        country = _iso2(row.get("Country Code") or "")
        years = sorted((key for key in row if "[YR" in key), reverse=True)
        for year in years:
            value = _number(row.get(year))
            if country and value is not None:
                result[country][name] = value
                break
    return dict(result)


def _merge_furniture_exports(result: dict[str, dict[str, float]], directory: Path) -> None:
    """Merge the latest furniture export values from the optional mirror file."""
    mirror = directory / "mirror.json"
    if not mirror.exists():
        return
    try:
        payload = json.loads(mirror.read_text(encoding="utf-8"))
        for country, rows in (payload.get("trade") or {}).items():
            furniture = rows.get("9403") if isinstance(rows, dict) else None
            if furniture:
                result.setdefault(country, {})["9403"] = max(
                    ((str(year), _number(value)) for year, value in furniture.items()),
                    key=lambda item: int(item[0]),
                )[1]
    except (OSError, ValueError, TypeError):
        return


def read_trade(directory: Path = COMTRADE_DIR, flow_code: str = "M") -> dict[str, dict[str, float]]:
    """Read the newest valid annual trade value per country and HS code."""
    latest: dict[str, dict[str, tuple[int, float]]] = defaultdict(dict)
    for path in sorted(directory.glob("*.csv")):
        for row in csv.DictReader(_open_csv(path)):
            if row.get("freqCode") != "A" or row.get("flowCode") != flow_code or row.get("partnerISO") != "W00":
                continue
            country, hs = _iso2(row.get("reporterISO") or ""), (row.get("cmdCode") or "").strip()
            year, value = _number(row.get("refYear")), _number(row.get("primaryValue"))
            if not country or not hs or year is None or value is None or value < 0:
                continue
            previous = latest[country].get(hs)
            if previous is None or int(year) > previous[0]:
                latest[country][hs] = (int(year), value)
    result = {country: {hs: value for hs, (_, value) in values.items()} for country, values in latest.items()}
    if flow_code == "X":
        _merge_furniture_exports(result, directory)
    return result


def _normalized_inputs(wdi: dict[str, dict[str, float]], trade: dict[str, dict[str, float]],
                       products: list[dict[str, Any]], exports: dict[str, dict[str, float]] | None,
                       external: dict[str, dict[str, float]] | None) -> dict[str, Any]:
    """Normalize shared country signals once before product-country projection."""
    countries = sorted(set(wdi) | set(trade))
    imports = {}
    for product in products:
        codes = {str(code) for code in (product.get("hs_codes") or [])}
        imports[product["product_id"]] = {
            country: sum(trade.get(country, {}).get(code, 0) for code in codes) or None
            for country in countries
        }
    exports = exports or {}
    external = external or {}
    return {
        "countries": countries,
        "imports": {product: minmax_normalize(values) for product, values in imports.items()},
        "furniture_export": minmax_normalize({country: sum(value for hs, value in rows.items() if hs.startswith("9403")) or None for country, rows in exports.items()}),
        "manufacturing": minmax_normalize({country: values.get("manufacturing_value_added") for country, values in wdi.items()}),
        "growth": minmax_normalize({country: values.get("manufacturing_growth") for country, values in wdi.items()}),
        "external": external,
    }


def _country_signals(product: dict[str, Any], country: str, normalized: dict[str, Any]) -> dict[str, float | None]:
    """Project normalized product and country evidence into score components."""
    category = product["category"]
    external = normalized["external"]
    return {
        "hs_import": normalized["imports"][product["product_id"]].get(country),
        "relevant_export": normalized["furniture_export"].get(country),
        "sector_consumption": (normalized["manufacturing"].get(country) if category == "metalworking"
                               else external.get("sector_consumption", {}).get(country)),
        "manufacturing_growth": normalized["growth"].get(country),
        "labor_cost_pressure": external.get("labor_cost_pressure", {}).get(country),
        "cement_consumption": external.get("cement_consumption", {}).get(country),
    }


def build_prior_rows(wdi: dict[str, dict[str, float]], trade: dict[str, dict[str, float]],
                     products: list[dict[str, Any]], exports: dict[str, dict[str, float]] | None = None,
                     external: dict[str, dict[str, float]] | None = None,
                     model_version: str = "country-prior-v1") -> list[dict[str, Any]]:
    """Build product-specific country prior rows with explicit missing signals."""
    normalized = _normalized_inputs(wdi, trade, products, exports, external)
    rows = []
    for product in products:
        category = product["category"]
        for country in normalized["countries"]:
            signals = _country_signals(product, country, normalized)
            result = country_prior_snapshot(signals, category)
            rows.append({"country_code": country, "product_id": product["product_id"],
                         "country_product_prior": result["score"], "data_coverage": result["data_coverage"],
                         "signal_values": signals, "limitations": result["limitations"],
                         "source_updated_at": {"comtrade": "local", "world_bank": "local"},
                         "model_version": model_version})
    return rows


def refresh(repo: MarketRepository | None = None) -> dict[str, Any]:
    """Load local country signals, score product priors, and persist the rows."""
    repo = repo or MarketRepository()
    external = {}
    source_meta = {}
    for key, env, url_env, aliases in (
        ("sector_consumption", "FAOSTAT_FORESTRY_PATH", "FAOSTAT_FORESTRY_URL", ("value", "production", "consumption")),
        ("labor_cost_pressure", "ILOSTAT_WAGES_PATH", "ILOSTAT_WAGES_URL", ("value", "earnings", "wage")),
        ("cement_consumption", "USGS_CEMENT_PATH", "USGS_CEMENT_URL", ("value", "cement_consumption", "production")),
    ):
        values, meta = configured_signal(env, url_env, DATA_DIR / "market_sources" / f"{key}.csv", aliases)
        external[key] = values
        source_meta[key] = meta
    rows = build_prior_rows(read_world_bank(), read_trade(), repo.list_product_tracks(), read_trade(flow_code="X"), external)
    for row in rows:
        row["source_updated_at"] = {**row.get("source_updated_at", {}), **source_meta}
    written = repo.upsert_country_product_priors(rows)
    return {"countries": len({row["country_code"] for row in rows}), "products": len({row["product_id"] for row in rows}), "rows": len(rows), "written": written}


if __name__ == "__main__":
    print(json.dumps(refresh(), indent=2))
