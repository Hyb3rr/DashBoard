"""Build the canonical Region Intelligence seed from local WDI and Comtrade CSVs."""

from __future__ import annotations

import csv
import io
import json
import math
import os
import statistics
import tempfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import pycountry

from ..config.settings import DATA_DIR, REGION_SEED_PATH


WB_DATA = DATA_DIR / "worldbank" / "Data.csv"
WB_METADATA = DATA_DIR / "worldbank" / "Series _Metadata.csv"
COMTRADE_DIR = DATA_DIR / "comtrade"
COMPLETE_YEAR = 2025
HS_PARENT = "8465"
HS_SUB = ("846510", "846520", "846591", "846592", "846593", "846594", "846595", "846596", "846599")
HS_NAMES = {
    "846510": "multi_operation", "846520": "machining_centres", "846591": "sawing",
    "846592": "planing_milling_moulding", "846593": "sanding_polishing",
    "846594": "bending_assembling", "846595": "drilling_morticing",
    "846596": "splitting_slicing", "846599": "other",
}
WB_CODES = {
    "gdp_current_usd": "NY.GDP.MKTP.CD", "gdp_per_capita": "NY.GDP.PCAP.CD",
    "gdp_growth": "NY.GDP.MKTP.KD.ZG", "population": "SP.POP.TOTL",
    "manufacturing_value_added": "NV.IND.MANF.CD", "manufacturing_share": "NV.IND.MANF.ZS",
    "manufacturing_growth": "NV.IND.MANF.KD.ZG", "industry_value_added": "NV.IND.TOTL.CD",
    "industry_share": "NV.IND.TOTL.ZS", "forest_area": "AG.LND.FRST.K2",
    "forest_share": "AG.LND.FRST.ZS", "population_growth": "SP.POP.GROW",
    "surface_area": "AG.SRF.TOTL.K2", "merchandise_imports": "TM.VAL.MRCH.CD.WT",
}
WB_LABELS = {
    "gdp_current_usd": "GDP (current US$)", "gdp_per_capita": "GDP per capita (current US$)",
    "gdp_growth": "GDP growth (annual %)", "population": "Population total",
    "manufacturing_value_added": "Manufacturing value added (current US$)",
    "manufacturing_share": "Manufacturing value added (% of GDP)",
    "manufacturing_growth": "Manufacturing value added (annual % growth)",
    "industry_value_added": "Industry including construction (current US$)",
    "industry_share": "Industry including construction (% of GDP)",
    "forest_area": "Forest area (sq. km)", "forest_share": "Forest area (% of land area)",
    "population_growth": "Population growth (annual %)", "surface_area": "Surface area (sq. km)",
    "merchandise_imports": "Merchandise imports (current US$)",
}


def _open_csv(path: Path):
    data = path.read_bytes()
    for encoding in ("utf-8-sig", "cp1252"):
        try:
            return io.StringIO(data.decode(encoding, errors="strict"))
        except UnicodeDecodeError:
            continue
    return io.StringIO(data.decode("utf-8", errors="replace"))


def parse_world_bank_metadata() -> dict[str, dict]:
    """Parse the composite WDI metadata export after its database marker."""
    text = WB_METADATA.read_bytes().decode("cp1252", errors="replace")
    marker = text.find("Data from database: World Development Indicators")
    if marker < 0:
        return {}
    section = text[marker:]
    header = section.find("Code,License Type")
    if header < 0:
        return {}
    rows = csv.DictReader(io.StringIO(section[header:]))
    metadata = {}
    for row in rows:
        code = (row.get("Code") or "").strip()
        if code in WB_CODES.values():
            metadata[code] = {"unit": row.get("Unit of measure"), "source": row.get("Source")}
    return metadata


def _iso2(iso3: str) -> str | None:
    value = (iso3 or "").strip().upper()
    if value == "XKX":
        return "XK"
    country = pycountry.countries.get(alpha_3=value)
    return country.alpha_2 if country else None


def _number(value: str | None) -> float | None:
    if value is None or value.strip().lower() in {"", "..", "null", "na", "n/a"}:
        return None
    try:
        result = float(value.replace(",", ""))
        return result if math.isfinite(result) else None
    except (TypeError, ValueError):
        return None


def _percentile(values: dict[str, float], key: str) -> float:
    if len(values) == 1:
        return 50.0
    ordered = sorted(values.values())
    value = values[key]
    rank = sum(1 for x in ordered if x < value) + (sum(1 for x in ordered if x == value) + 1) / 2
    return round(100 * (rank - 1) / (len(ordered) - 1), 4)


def _points(percentile: float) -> int:
    return 25 if percentile < 25 else 50 if percentile < 50 else 75 if percentile < 75 else 100


def _level(score: float | None) -> str:
    if score is None:
        return "unknown"
    return "low" if score < 25 else "medium" if score < 50 else "high" if score < 75 else "very_high"


def _weighted(signals: list[tuple[str, float | None, float]], raw: dict, source: str) -> tuple[float | None, list[dict]]:
    present = [(name, value, weight) for name, value, weight in signals if value is not None]
    if not present:
        return None, []
    total_weight = sum(x[2] for x in present)
    score = sum(x[1] * x[2] for x in present) / total_weight
    evidence = []
    for name, value, weight in present:
        evidence.append({"signal": name, "source": source, "raw_value": raw.get(name),
                         "percentile": round(value, 4), "points": _points(value),
                         "weight": round(weight / total_weight, 4),
                         "effect": round(value * weight / total_weight, 2)})
    return round(score, 2), evidence


def parse_world_bank() -> tuple[dict[str, dict], dict]:
    if not WB_DATA.exists() or not WB_METADATA.exists():
        raise FileNotFoundError("World Bank Data.csv or Series _Metadata.csv is missing")
    metadata = parse_world_bank_metadata()
    rows = []
    with _open_csv(WB_DATA) as handle:
        for row in csv.DictReader(handle):
            if row.get("Series Code") in WB_CODES.values():
                code = _iso2(row.get("Country Code", ""))
                if not code:
                    continue
                rows.append((code, row))
    result = defaultdict(dict)
    years = [str(year) + " [YR" + str(year) + "]" for year in range(2016, 2026)]
    reverse = {value: key for key, value in WB_CODES.items()}
    for country, row in rows:
        name = reverse[row["Series Code"]]
        for year in reversed(years):
            value = _number(row.get(year))
            if value is not None:
                result[country][name] = {"value": value, "data_date": int(year[:4]),
                                         "label": WB_LABELS[name], "indicator_code": row["Series Code"],
                                         "source": "World Bank WDI", "unit": metadata.get(row["Series Code"], {}).get("unit")}
                break
    metadata = {"countries": len(result), "indicators": len(WB_CODES), "source_file": WB_DATA.name}
    return dict(result), metadata


def parse_comtrade() -> tuple[dict[str, dict[str, dict[int, float]]], dict]:
    files = sorted(COMTRADE_DIR.glob("*.csv"))
    if not files:
        raise FileNotFoundError("No Comtrade CSV files found")
    trade = defaultdict(lambda: defaultdict(dict))
    rows_seen = 0
    for path in files:
        with _open_csv(path) as handle:
            for row in csv.DictReader(handle):
                rows_seen += 1
                if row.get("freqCode") != "A" or row.get("flowCode") != "M" or row.get("partnerISO") != "W00":
                    continue
                hs = str(row.get("cmdCode") or "").strip()
                if hs != HS_PARENT and hs not in HS_SUB:
                    continue
                country = _iso2(row.get("reporterISO", ""))
                value = _number(row.get("primaryValue"))
                year = int(row.get("refYear") or 0)
                if not country or value is None or not year:
                    continue
                trade[country][hs][year] = value
    diagnostics = {"files": len(files), "years": sorted({year for c in trade.values() for h in c.values() for year in h}),
                   "countries": len(trade), "rows_seen": rows_seen, "latest_complete_year": COMPLETE_YEAR}
    return {c: dict(hs) for c, hs in trade.items()}, diagnostics


def _growth(series: dict[int, float], latest: int) -> float | None:
    end = series.get(latest)
    for span in (3, 2):
        start = series.get(latest - span)
        if end is not None and start is not None and start > 0 and end >= 0:
            return (end / start) ** (1 / span) - 1
    return None


def _trade_scores(trade: dict[str, dict[str, dict[int, float]]]) -> dict[str, dict]:
    countries = {c for c, hs in trade.items() if HS_PARENT in hs and COMPLETE_YEAR in hs[HS_PARENT]}
    parent_latest = {c: trade[c][HS_PARENT][COMPLETE_YEAR] for c in countries}
    growth_raw = {c: _growth(trade[c][HS_PARENT], COMPLETE_YEAR) for c in countries}
    growth_valid = {c: v for c, v in growth_raw.items() if v is not None}
    stability_raw = {}
    breadth_raw = {}
    for c in countries:
        series = [trade[c][HS_PARENT][y] for y in range(2021, 2026) if y in trade[c][HS_PARENT]]
        if len(series) >= 3 and statistics.mean(series) > 0:
            stability_raw[c] = statistics.pstdev(series) / statistics.mean(series)
        sub = [trade[c].get(h, {}).get(COMPLETE_YEAR, 0) for h in HS_SUB]
        total = sum(sub)
        if total > 0:
            shares = [v / total for v in sub if v > 0]
            entropy = -sum(p * math.log(p) for p in shares) / math.log(len(HS_SUB)) if shares else 0
            coverage = sum(1 for v in sub if v / total >= 0.02) / len(HS_SUB)
            breadth_raw[c] = 50 * entropy + 50 * coverage
    stability_pct = {c: 100 - _percentile(stability_raw, c) for c in stability_raw}
    breadth_pct = {c: _percentile(breadth_raw, c) for c in breadth_raw}
    size_pct = {c: _percentile(parent_latest, c) for c in parent_latest}
    growth_pct = {c: _percentile(growth_valid, c) for c in growth_valid}
    output = {}
    for c in countries:
        signals = [("import_size", size_pct.get(c), .55), ("growth", growth_pct.get(c), .25),
                   ("stability", stability_pct.get(c), .10), ("breadth", breadth_pct.get(c), .10)]
        demand, evidence = _weighted(signals, {"import_size": parent_latest[c], "growth": growth_raw.get(c),
                                               "stability": stability_raw.get(c), "breadth": breadth_raw.get(c)}, "UN Comtrade")
        opportunities = []
        for hs in HS_SUB:
            series = trade[c].get(hs, {})
            latest = series.get(COMPLETE_YEAR)
            if latest is None:
                continue
            values = {country: trade[country].get(hs, {}).get(COMPLETE_YEAR) for country in countries}
            values = {country: value for country, value in values.items() if value is not None}
            hs_size = _percentile(values, c)
            hs_growth = _growth(series, COMPLETE_YEAR)
            all_growth = {country: _growth(trade[country].get(hs, {}), COMPLETE_YEAR) for country in countries}
            all_growth = {country: value for country, value in all_growth.items() if value is not None}
            growth_score = _percentile(all_growth, c) if hs_growth is not None else None
            score = hs_size if growth_score is None else round(hs_size * .7 + growth_score * .3, 2)
            opportunities.append({"hs_code": hs, "product": HS_NAMES[hs], "score": score,
                                  "level": _level(score), "latest_value": latest, "data_date": COMPLETE_YEAR,
                                  "growth": hs_growth})
        opportunities.sort(key=lambda item: (-item["score"], item["hs_code"]))
        output[c] = {"product_demand": demand, "product_evidence": evidence,
                     "series": [{"year": year, "value": value} for year, value in sorted(trade[c][HS_PARENT].items())],
                     "sub_hs": {hs: {"product": HS_NAMES[hs], "series": [{"year": y, "value": v} for y, v in sorted(trade[c].get(hs, {}).items())]} for hs in HS_SUB if hs in trade[c]},
                     "opportunities": opportunities}
    return output


def _build_market(wdi: dict[str, dict], trade: dict[str, dict[str, dict[int, float]]]) -> dict[str, dict]:
    all_values = defaultdict(dict)
    for country, indicators in wdi.items():
        for name, item in indicators.items():
            all_values[name][country] = item["value"]
    percentiles = {name: {country: _percentile(values, country) for country in values} for name, values in all_values.items()}
    trade_scores = _trade_scores(trade)
    result = {}
    for country in set(wdi) | set(trade):
        indicators = wdi.get(country, {})
        raw = {name: item["value"] for name, item in indicators.items()}
        def p(name): return percentiles.get(name, {}).get(country)
        capacity, cap_evidence = _weighted([("gdp_current_usd", p("gdp_current_usd"), .25),
                                            ("gdp_per_capita", p("gdp_per_capita"), .25),
                                            ("merchandise_imports", p("merchandise_imports"), .25),
                                            ("population", p("population"), .25)], raw, "World Bank WDI")
        forest = _weighted([("forest_area", p("forest_area"), .60), ("forest_share", p("forest_share"), .40)], raw, "World Bank WDI")[0]
        fit, fit_evidence = _weighted([("manufacturing_value_added", p("manufacturing_value_added"), .30),
                                       ("manufacturing_share", p("manufacturing_share"), .20),
                                       ("manufacturing_growth", p("manufacturing_growth"), .15),
                                       ("industry_value_added", p("industry_value_added"), .15),
                                       ("industry_share", p("industry_share"), .15),
                                       ("forest_proxy", forest, .05)], raw, "World Bank WDI")
        demand = trade_scores.get(country)
        components = {"product_demand": demand["product_demand"] if demand else None,
                      "industrial_fit": fit if len(fit_evidence) >= 3 else None,
                      "market_capacity": capacity if len(cap_evidence) >= 2 else None}
        economic_parts = [("market_capacity", components["market_capacity"], .40),
                          ("industrial_fit", components["industrial_fit"], .60)]
        economic_present = [(key, value, weight) for key, value, weight in economic_parts if value is not None]
        economic_potential = (round(sum(value * weight for _, value, weight in economic_present) /
                                    sum(weight for _, _, weight in economic_present), 2)
                              if economic_present else None)
        machine_demand = components["product_demand"]
        score = (round(economic_potential * .40 + machine_demand * .60, 2)
                 if economic_potential is not None and machine_demand is not None else None)
        components["economic_potential"] = economic_potential
        components["machine_demand"] = machine_demand
        economic = {"schema_version": 1, "indicators": indicators, "trade": {"woodworking_machinery": {"hs_code": HS_PARENT, "latest_complete_year": COMPLETE_YEAR, "series": demand["series"] if demand else [], "sub_hs": demand["sub_hs"] if demand else {}}}, "market_components": components, "economic_potential": economic_potential, "machine_demand": machine_demand, "market_score": score, "market_level": _level(score), "market_evidence": (demand["product_evidence"] if demand else []) + cap_evidence + fit_evidence, "product_opportunities": demand["opportunities"] if demand else [], "refreshed_at": datetime.now(timezone.utc).isoformat()}
        result[country] = economic
    return result


def refresh(seed_path: Path = REGION_SEED_PATH) -> dict:
    existing = json.loads(seed_path.read_text(encoding="utf-8")) if seed_path.exists() else []
    if not isinstance(existing, list):
        raise ValueError("region seed must be a JSON array")
    wdi, wb_diag = parse_world_bank()
    trade, trade_diag = parse_comtrade()
    market = _build_market(wdi, trade)
    by_code = {item["country_code"]: item for item in existing if item.get("country_code")}
    output = []
    for code in sorted(set(by_code) | set(market)):
        old = dict(by_code.get(code, {}))
        if code not in old:
            country = pycountry.countries.get(alpha_2=code)
            old.update({"country_code": code, "country_name": country.name if country else code, "cultural_context": [], "conflict_indicators": [], "sources": []})
        old["economic_indicators"] = market.get(code, {"schema_version": 1, "indicators": {}, "trade": {}, "market_components": {}, "market_score": None, "market_level": "unknown", "market_evidence": [], "product_opportunities": []})
        old["updated_at"] = datetime.now(timezone.utc).isoformat()
        output.append(old)
    seed_path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{seed_path.name}.", suffix=".tmp", dir=seed_path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(output, handle, ensure_ascii=False, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, seed_path)
        return {"world_bank": wb_diag, "comtrade": trade_diag, "countries": len(output), "scored": sum(1 for x in output if x["economic_indicators"].get("market_score") is not None)}
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def main() -> None:
    report = refresh()
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
