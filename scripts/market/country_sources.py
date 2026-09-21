"""Country-level source adapters with cacheable, provenance-preserving snapshots."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import tempfile
import xml.etree.ElementTree as ET
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pycountry


def iso2(value: str) -> str | None:
    code = (value or "").strip().upper()
    if len(code) == 2:
        return code
    if code.isdigit():
        country = pycountry.countries.get(numeric=code.zfill(3))
        return country.alpha_2 if country else None
    country = pycountry.countries.get(alpha_3=code)
    if country:
        return country.alpha_2
    for candidate in pycountry.countries:
        if candidate.name.upper() == code:
            return candidate.alpha_2
    return None


def download_snapshot(url: str, destination: Path, timeout: float = 60.0) -> dict[str, Any]:
    """Download atomically and return provenance; caller supplies official URL."""
    request = urllib.request.Request(url, headers={"User-Agent": "IPIntel-Market/1.0"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        content = response.read()
    digest = hashlib.sha256(content).hexdigest()
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent)
    try:
        with open(fd, "wb", closefd=True) as handle:
            handle.write(content)
            handle.flush()
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return {"url": url, "sha256": digest, "downloaded_at": datetime.now(timezone.utc).isoformat()}


def read_normalized_signal(path: Path, value_aliases: tuple[str, ...]) -> dict[str, float]:
    """Read normalized CSV/ZIP rows: country_code, value, year."""
    if path.suffix.lower() == ".zip":
        with zipfile.ZipFile(path) as archive:
            members = [name for name in archive.namelist() if name.lower().endswith(".csv")]
            if not members:
                return {}
            text = archive.read(members[0]).decode("utf-8-sig", errors="replace")
            rows = csv.DictReader(io.StringIO(text))
    else:
        rows = csv.DictReader(path.open(encoding="utf-8-sig", newline=""))
    latest: dict[str, tuple[int, float]] = {}
    for row in rows:
        country = iso2(row.get("country_code") or row.get("iso2") or row.get("iso3") or "")
        value = next((row.get(alias) for alias in value_aliases if row.get(alias) not in (None, "")), None)
        try:
            year = int(row.get("year") or 0)
            number = float(value)
        except (TypeError, ValueError):
            continue
        if country and number == number and (country not in latest or year >= latest[country][0]):
            latest[country] = (year, number)
    return {country: value for country, (_, value) in latest.items()}


def configured_signal(path_env: str, url_env: str, cache_path: Path, aliases: tuple[str, ...]) -> tuple[dict[str, float], dict[str, Any]]:
    """Use local cache first; URL download is opt-in through environment."""
    path = Path(os.getenv(path_env, str(cache_path)))
    provenance: dict[str, Any] = {"source": path_env, "path": str(path)}
    if not path.exists() and os.getenv(url_env):
        provenance.update(download_snapshot(os.environ[url_env], path))
    if not path.exists():
        return {}, {**provenance, "status": "unavailable"}
    return read_normalized_signal(path, aliases), {**provenance, "status": "loaded"}


def _request_bytes(url: str, params: dict[str, Any] | None = None, timeout: float = 60.0) -> bytes:
    if params:
        from urllib.parse import urlencode
        separator = "&" if "?" in url else "?"
        url = f"{url}{separator}{urlencode(params, doseq=True)}"
    request = urllib.request.Request(url, headers={"User-Agent": "IPIntel-Market/1.0", "Accept": "application/json, application/xml, text/xml"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def _record_country(row: dict[str, Any]) -> str | None:
    for key in ("country_code", "iso2", "ISO2", "iso3", "ISO3", "Area Code (M49)", "M49", "m49_code", "ReporterISO", "RefArea", "REF_AREA", "area_code"):
        value = row.get(key)
        if value not in (None, ""):
            result = iso2(str(value))
            if result:
                return result
    for key in ("Area", "area", "Country", "country", "RefAreaName", "country_name_en"):
        value = row.get(key)
        if value:
            result = iso2(str(value))
            if result:
                return result
    return None


def _record_year(row: dict[str, Any]) -> int | None:
    for key in ("year", "Year", "TIME_PERIOD", "time_period", "period"):
        try:
            return int(str(row.get(key, "")).strip()[:4])
        except (TypeError, ValueError):
            continue
    return None


def _record_value(row: dict[str, Any], aliases: tuple[str, ...]) -> float | None:
    for key in aliases:
        value = row.get(key)
        if value in (None, "", "..", "NA", "N/A"):
            continue
        try:
            number = float(str(value).replace(",", ""))
        except (TypeError, ValueError):
            continue
        if number == number and abs(number) != float("inf"):
            return number
    return None


def _rows_from_json(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("data", "Data", "records", "results", "observations"):
        value = payload.get(key)
        if isinstance(value, list):
            return [row for row in value if isinstance(row, dict)]
    return []


def _bgs_rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for feature in payload.get("features", []) if isinstance(payload, dict) else []:
        properties = feature.get("properties") if isinstance(feature, dict) else None
        if not isinstance(properties, dict):
            continue
        if properties.get("bgs_statistic_type_trans") != "Production":
            continue
        # Finished cement is the comparable cement-production signal; clinker
        # is an intermediate and must not be summed into finished cement.
        if properties.get("bgs_commodity_trans") != "cement, finished":
            continue
        rows.append({
            "country_code": properties.get("country_iso2_code"),
            "year": properties.get("year"),
            "value": properties.get("quantity"),
        })
    return rows


def _rows_from_csv(content: bytes) -> list[dict[str, Any]]:
    text = content.decode("utf-8-sig", errors="replace")
    return list(csv.DictReader(io.StringIO(text)))


def _parse_ilostat_sdmx_json(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse both simple records and the compact SDMX-JSON dataSets shape."""
    if isinstance(payload.get("data"), dict):
        nested = dict(payload["data"])
        nested.setdefault("structure", payload.get("structure", {}))
        payload = nested
    simple = _rows_from_json(payload)
    if simple:
        return simple
    structure = payload.get("structure") or {}
    if payload.get("structures") and payload.get("dataSets"):
        rows: list[dict[str, Any]] = []
        for dataset in payload.get("dataSets", []):
            schema = payload["structures"][dataset.get("structure", 0)]
            series_dimensions = schema.get("dimensions", {}).get("series", [])
            observation_dimensions = schema.get("dimensions", {}).get("observation", [])
            series_values = [dimension.get("values", []) for dimension in series_dimensions]
            time_values = (observation_dimensions[0].get("values", []) if observation_dimensions else [])
            for series_key, series in (dataset.get("series") or {}).items():
                indexes = [int(part) for part in str(series_key).split(":")]
                base: dict[str, Any] = {}
                for dimension, choices, index in zip(series_dimensions, series_values, indexes):
                    if index < len(choices):
                        choice = choices[index]
                        base[dimension.get("id", "")] = choice.get("id") if isinstance(choice, dict) else choice
                for observation_key, observation in (series.get("observations") or {}).items():
                    time_index = int(str(observation_key).split(":", 1)[0])
                    row = dict(base)
                    if time_index < len(time_values):
                        choice = time_values[time_index]
                        row["TIME_PERIOD"] = choice.get("id") if isinstance(choice, dict) else choice
                    row["value"] = observation[0] if isinstance(observation, list) and observation else observation
                    rows.append(row)
        return rows
    dimensions = structure.get("dimensions", {}).get("observation", [])
    time_dimension = (structure.get("dimensions", {}).get("time") or [{}])[0]
    names = [dimension.get("id") for dimension in dimensions]
    values = [dimension.get("values", []) for dimension in dimensions]
    rows: list[dict[str, Any]] = []
    for dataset in payload.get("dataSets", []):
        for key, observation in (dataset.get("observations") or {}).items():
            indexes = [int(part) for part in str(key).split(":")]
            row = {"value": observation[0] if isinstance(observation, list) and observation else observation}
            for name, choices, index in zip(names, values, indexes):
                if name and index < len(choices):
                    row[name] = choices[index].get("id") if isinstance(choices[index], dict) else choices[index]
            if time_dimension and len(indexes) > len(names):
                time_index = indexes[-1]
                time_values = time_dimension.get("values", [])
                if time_index < len(time_values):
                    choice = time_values[time_index]
                    row["TIME_PERIOD"] = choice.get("id") if isinstance(choice, dict) else choice
            rows.append(row)
    return rows


def _parse_ilostat_sdmx_xml(content: bytes) -> list[dict[str, Any]]:
    root = ET.fromstring(content)
    rows = []
    for observation in root.iter():
        if observation.tag.rsplit("}", 1)[-1] != "Obs":
            continue
        row = dict(observation.attrib)
        for child in observation:
            row[child.tag.rsplit("}", 1)[-1]] = next(iter(child.attrib.values()), child.text)
        rows.append(row)
    return rows


def _write_normalized_rows(rows: list[dict[str, Any]], destination: Path, aliases: tuple[str, ...]) -> dict[str, Any]:
    latest: dict[str, tuple[int, float]] = {}
    for row in rows:
        country, year, value = _record_country(row), _record_year(row), _record_value(row, aliases)
        if country and year and value is not None and (country not in latest or year >= latest[country][0]):
            latest[country] = (year, value)
    if not latest:
        return {"status": "invalid", "rows": 0}
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent)
    try:
        with open(fd, "w", encoding="utf-8", newline="", closefd=True) as handle:
            writer = csv.DictWriter(handle, fieldnames=("country_code", "year", "value"))
            writer.writeheader()
            writer.writerows({"country_code": country, "year": year, "value": value} for country, (year, value) in sorted(latest.items()))
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return {"status": "updated", "rows": len(latest), "path": str(destination)}


def refresh_faostat(destination: Path, url: str | None = None, params: dict[str, Any] | None = None) -> dict[str, Any]:
    url = url or os.getenv("FAOSTAT_FORESTRY_API_URL")
    if not url:
        return {"status": "not_configured", "source": "faostat"}
    try:
        configured = os.getenv("FAOSTAT_FORESTRY_API_PARAMS", "")
        request_params = params or (json.loads(configured) if configured else {})
        content = _request_bytes(url, request_params)
        aliases = ("value", "Value", "production", "Production", "production_m3", "production_t", "consumption", "Consumption")
        try:
            rows = _rows_from_json(json.loads(content.decode("utf-8")))
        except (UnicodeDecodeError, json.JSONDecodeError):
            rows = _rows_from_csv(content)
        result = _write_normalized_rows(rows, destination, aliases)
        return {**result, "source": "faostat", "url": url}
    except Exception as exc:
        return {"status": "failed", "source": "faostat", "error": type(exc).__name__, "message": str(exc)[:240]}


def refresh_ilostat(destination: Path, url: str | None = None, params: dict[str, Any] | None = None) -> dict[str, Any]:
    url = url or os.getenv("ILOSTAT_WAGES_API_URL")
    if not url:
        return {"status": "not_configured", "source": "ilostat"}
    try:
        configured = os.getenv("ILOSTAT_WAGES_API_PARAMS", "")
        request_params = params or (json.loads(configured) if configured else {})
        content = _request_bytes(url, request_params)
        try:
            rows = _parse_ilostat_sdmx_json(json.loads(content.decode("utf-8")))
        except (UnicodeDecodeError, json.JSONDecodeError):
            rows = _parse_ilostat_sdmx_xml(content)
        if any(row.get("CUR") for row in rows):
            rows = [row for row in rows if row.get("SEX") in (None, "SEX_T") and row.get("CUR") in (None, "CUR_TYPE_USD")]
        result = _write_normalized_rows(rows, destination, ("value", "OBS_VALUE", "ObsValue", "earnings", "wage", "WAGE"))
        return {**result, "source": "ilostat", "url": url}
    except Exception as exc:
        return {"status": "failed", "source": "ilostat", "error": type(exc).__name__, "message": str(exc)[:240]}


def refresh_bgs_cement(destination: Path, url: str | None = None) -> dict[str, Any]:
    url = url or os.getenv("BGS_CEMENT_API_URL")
    if not url:
        return {"status": "not_configured", "source": "bgs_cement"}
    try:
        from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
        parsed = urlsplit(url)
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        query.setdefault("limit", "1000")
        rows: list[dict[str, Any]] = []
        offset = 0
        matched = None
        for _ in range(100):
            query["offset"] = str(offset)
            page_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), parsed.fragment))
            payload = json.loads(_request_bytes(page_url, timeout=60).decode("utf-8"))
            page = payload.get("features", [])
            rows.extend(_bgs_rows(payload))
            matched = payload.get("numberMatched", matched)
            if not page or (matched is not None and offset + len(page) >= int(matched)):
                break
            offset += len(page)
        result = _write_normalized_rows(rows, destination, ("value", "quantity"))
        result["pages"] = (offset // int(query["limit"])) + 1 if rows else 0
        return {**result, "source": "bgs_cement", "url": url}
    except Exception as exc:
        return {"status": "failed", "source": "bgs_cement", "error": type(exc).__name__, "message": str(exc)[:240]}


def refresh_country_sources(base_path: Path, now: datetime | None = None) -> dict[str, Any]:
    """Refresh configured API snapshots; USGS intentionally remains manual."""
    base_path.mkdir(parents=True, exist_ok=True)
    results = {
        "faostat": refresh_faostat(base_path / "sector_consumption.csv"),
        "ilostat": refresh_ilostat(base_path / "labor_cost_pressure.csv"),
        "bgs_cement": refresh_bgs_cement(base_path / "cement_consumption.csv"),
    }
    usgs = base_path / "cement_consumption.csv"
    results["usgs"] = {"source": "usgs", "status": "superseded_by_bgs" if usgs.exists() else "not_used"}
    statuses = {result["status"] for result in results.values()}
    status = "updated" if "updated" in statuses else ("partial" if "loaded_manual" in statuses else "not_configured")
    return {"status": status, "sources": results, "refreshed_at": (now or datetime.now(timezone.utc)).isoformat()}
