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
    raw = path.read_bytes()
    for encoding in ("utf-8-sig", "cp1252"):
        try:
            return raw.decode(encoding).splitlines()
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace").splitlines()


def _number(value: Any) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if number == number and abs(number) != float("inf") else None


_iso2 = iso2


def read_world_bank(path: Path = WORLD_BANK) -> dict[str, dict[str, float]]:
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


def read_trade(directory: Path = COMTRADE_DIR, flow_code: str = "M") -> dict[str, dict[str, float]]:
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
        mirror = directory / "mirror.json"
        if mirror.exists():
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
                pass
    return result


def build_prior_rows(wdi: dict[str, dict[str, float]], trade: dict[str, dict[str, float]],
                     products: list[dict[str, Any]], exports: dict[str, dict[str, float]] | None = None,
                     external: dict[str, dict[str, float]] | None = None,
                     model_version: str = "country-prior-v1") -> list[dict[str, Any]]:
    countries = sorted(set(wdi) | set(trade))
    import_raw = {}
    for product in products:
        codes = {str(code) for code in (product.get("hs_codes") or [])}
        import_raw[product["product_id"]] = {country: sum(trade.get(country, {}).get(code, 0) for code in codes) or None for country in countries}
    normalized_imports = {product: minmax_normalize(values) for product, values in import_raw.items()}
    exports = exports or {}
    furniture_export = minmax_normalize({country: sum(value for hs, value in rows.items() if hs.startswith("9403")) or None for country, rows in exports.items()})
    manufacturing = minmax_normalize({country: values.get("manufacturing_value_added") for country, values in wdi.items()})
    growth = minmax_normalize({country: values.get("manufacturing_growth") for country, values in wdi.items()})
    external = external or {}
    rows = []
    for product in products:
        category = product["category"]
        product_id = product["product_id"]
        for country in countries:
            signals = {
                "hs_import": normalized_imports[product_id].get(country),
                "relevant_export": furniture_export.get(country),
                "sector_consumption": (manufacturing.get(country) if category == "metalworking"
                                        else external.get("sector_consumption", {}).get(country)),
                "manufacturing_growth": growth.get(country),
                "labor_cost_pressure": external.get("labor_cost_pressure", {}).get(country),
                "cement_consumption": external.get("cement_consumption", {}).get(country),
            }
            result = country_prior_snapshot(signals, category)
            rows.append({"country_code": country, "product_id": product_id,
                         "country_product_prior": result["score"], "data_coverage": result["data_coverage"],
                         "signal_values": signals, "limitations": result["limitations"],
                         "source_updated_at": {"comtrade": "local", "world_bank": "local"},
                         "model_version": model_version})
    return rows


def refresh(repo: MarketRepository | None = None) -> dict[str, Any]:
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
