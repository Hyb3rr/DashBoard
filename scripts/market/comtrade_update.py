"""Scheduler-owned, bounded Comtrade mirror refresh."""
from __future__ import annotations

import json
import os
import tempfile
import time
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import pycountry

from scripts.market import market_refresh
from app.core.market_catalog import catalog_rows

PREVIEW_URL = "https://comtradeapi.un.org/public/v1/preview/C/A/HS"
DATA_URL = "https://comtradeapi.un.org/data/v1/get/C/A/HS"
MIRROR_PATH = market_refresh.MIRROR_CACHE
RETRYABLE_STATUS = {408, 429, 500, 502, 503, 504}


def _numeric_code(country: str) -> str | None:
    """Return a country's ISO numeric code when it is recognized."""
    item = pycountry.countries.get(alpha_2=country.upper())
    return item.numeric if item else None


def _retry_delay(error: HTTPError, attempt: int) -> float:
    """Choose the server-requested delay or a bounded exponential backoff."""
    header = error.headers.get("Retry-After") if error.headers else None
    if header:
        try:
            return max(0.0, float(header))
        except ValueError:
            try:
                return max(0.0, (parsedate_to_datetime(header) - datetime.now(timezone.utc)).total_seconds())
            except (TypeError, ValueError, OverflowError):
                pass
    return min(30.0, 2 ** attempt)


def _request_json(request: Request, timeout: float = 30.0, opener=urlopen,
                  sleep_fn=time.sleep, max_attempts: int | None = None) -> dict:
    """Fetch and decode JSON with bounded retries for transient failures."""
    attempts = max_attempts or int(os.getenv("COMTRADE_MAX_ATTEMPTS", "3"))
    for attempt in range(attempts):
        try:
            with opener(request, timeout=timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as error:
            if error.code not in RETRYABLE_STATUS or attempt + 1 >= attempts:
                raise RuntimeError(f"Comtrade request failed with HTTP {error.code}") from None
            sleep_fn(_retry_delay(error, attempt))
        except (URLError, TimeoutError, OSError, json.JSONDecodeError) as error:
            if attempt + 1 >= attempts:
                raise RuntimeError(f"Comtrade request failed: {type(error).__name__}") from None
            sleep_fn(min(30.0, 2 ** attempt))
    raise RuntimeError("Comtrade request exhausted")


def _fetch(country: str, year: int, timeout: float = 30.0, flow_code: str = "M", cmd_code: str | None = None) -> list[dict]:
    """Fetch one country's Comtrade observations for a year and trade flow."""
    numeric = _numeric_code(country)
    if not numeric:
        return []
    params = {"period": str(year), "reporterCode": numeric, "cmdCode": cmd_code or market_refresh.HS_PARENT,
              "flowCode": flow_code, "partnerCode": "0", "maxrecords": "500", "format": "json",
              "includeDesc": "false"}
    api_key = os.getenv("COMTRADE_API_KEY")
    endpoint = DATA_URL if api_key else PREVIEW_URL
    if api_key:
        params["subscription-key"] = api_key
    request = Request(f"{endpoint}?{urlencode(params)}", headers={"User-Agent": "IPIntel-Comtrade/1.0"})
    payload = _request_json(request, timeout=float(os.getenv("COMTRADE_REQUEST_TIMEOUT", timeout)))
    return payload.get("data", []) if isinstance(payload, dict) else []


def _aggregate(rows: list[dict], country: str, year: int) -> float | None:
    """Read bilateral mirror exports; retain legacy row fixtures for tests."""
    total = 0.0
    found = False
    seen = set()
    for index, row in enumerate(rows or []):
        if not isinstance(row, dict):
            continue
        mirror = row.get("mirrorPrimaryValue")
        if mirror is not None:
            key = (row.get("reporterCode"), row.get("partnerCode"), row.get("refYear", year), row.get("cmdCode", market_refresh.HS_PARENT), row.get("flowCode", "M"))
            if key in seen:
                continue
            seen.add(key)
            value = mirror
        else:
            partner = str(row.get("partnerISO") or row.get("partnerDesc") or "").upper()
            if partner not in {country.upper(), "WORLD"} and row.get("partnerCode") not in {0, "0", _numeric_code(country)}:
                continue
            value = row.get("primaryValue")
            key = (row.get("reporterCode"), row.get("partnerCode"), row.get("refYear", year), row.get("cmdCode", market_refresh.HS_PARENT), row.get("flowCode", "X"), index)
        try:
            value = float(value)
        except (TypeError, ValueError):
            continue
        if value >= 0:
            total += value
            found = True
    return total if found else None


def _primary_countries() -> list[str]:
    """Return catalog countries enabled as primary markets."""
    return sorted(item["country_code"] for item in catalog_rows() if item["primary_market"])


def _load_mirror(path: Path) -> tuple[dict, dict, dict]:
    """Load trade, provenance, and freshness maps from the mirror file."""
    current = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    return current.get("trade") or {}, current.get("provenance") or {}, current.get("checks") or {}


def _record_observation(trade: dict, provenance: dict, country: str, year: int, value: float) -> None:
    """Store a mirrored value and its country-level provenance."""
    trade.setdefault(country, {}).setdefault(market_refresh.HS_PARENT, {})[str(year)] = value
    entry = provenance.setdefault(country, {"method": "mirror", "confidence": "medium", "years": []})
    if isinstance(entry, str):
        entry = {"method": entry, "confidence": "medium", "years": []}
        provenance[country] = entry
    years = entry.setdefault("years", [])
    if str(year) not in years:
        years.append(str(year))
    entry["method"], entry["confidence"] = "mirror", "medium"


def _refresh_observations(countries: list[str], years: list[int], fetcher, now: datetime,
                          max_age: timedelta, trade: dict, provenance: dict, checks: dict) -> dict:
    """Refresh stale country-year observations while preserving good cached values."""
    result = {"updated": 0, "failed": 0, "skipped": 0, "failed_requests": []}
    for country in countries:
        for year in years:
            stamp = (checks.get(country) or {}).get(str(year))
            if stamp:
                try:
                    if now - datetime.fromisoformat(stamp) < max_age:
                        result["skipped"] += 1
                        continue
                except ValueError:
                    pass
            try:
                value = _aggregate(fetcher(country, year), country, year)
            except Exception:
                result["failed"] += 1
                result["failed_requests"].append(f"{country}:{year}")
                continue
            checks.setdefault(country, {})[str(year)] = now.isoformat()
            if value is None:
                continue
            _record_observation(trade, provenance, country, year, value)
            result["updated"] += 1
    return result


def _write_mirror(path: Path, payload: dict) -> None:
    """Atomically persist a mirror snapshot and clean up failed temporary writes."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _refresh_furniture_exports(countries: list[str], years: list[int], fetcher, trade: dict) -> dict:
    """Refresh optional furniture-export observations and summarize their outcome."""
    report = {"status": "disabled", "updated": 0, "failed": 0}
    if os.getenv("COMTRADE_FURNITURE_EXPORT_REFRESH", "false").strip().lower() not in {"1", "true", "yes", "on"}:
        return report
    report["status"] = "updated"
    for country in countries:
        for year in years:
            try:
                value = _aggregate(fetcher(country, year, flow_code="X", cmd_code="9403"), country, year)
                if value is not None:
                    trade.setdefault(country, {}).setdefault("9403", {})[str(year)] = value
                    report["updated"] += 1
            except Exception:
                report["failed"] += 1
    report["status"] = "updated" if report["updated"] else "no_data"
    return report


def _refresh_market_read_model(path: Path) -> dict:
    """Refresh the derived market read model when using the canonical mirror."""
    if path != MIRROR_PATH:
        return {}
    result = {"market_refresh": market_refresh.refresh()}
    if os.getenv("POSTGRES_DSN"):
        from ..db.repositories import RegionRepository
        seed = json.loads(market_refresh.REGION_SEED_PATH.read_text(encoding="utf-8"))
        RegionRepository().seed(seed)
        result["read_model"] = {"status": "updated", "countries": len(seed)}
    return result


def refresh(countries: list[str] | None = None, years: list[int] | None = None,
            fetcher=_fetch, path: str | Path = MIRROR_PATH, now: datetime | None = None) -> dict:
    """Refresh uncached recent observations, preserving good state on failure."""
    path = Path(path)
    trade, provenance, checks = _load_mirror(path)
    countries = countries if countries is not None else _primary_countries()
    years = years or [market_refresh.COMPLETE_YEAR - offset for offset in range(market_refresh.MAX_TRADE_AGE_YEARS + 1)]
    now = now or datetime.now(timezone.utc)
    max_age = timedelta(hours=float(os.getenv("COMTRADE_MIRROR_RECHECK_HOURS", "24")))
    outcome = _refresh_observations(countries, years, fetcher, now, max_age, trade, provenance, checks)
    payload = {"schema_version": 2, "refreshed_at": now.isoformat(), "trade": trade, "provenance": provenance, "checks": checks}
    _write_mirror(path, payload)
    furniture_report = _refresh_furniture_exports(countries, years, fetcher, trade)
    report = {"status": "updated", "countries": len(countries), "observations": outcome["updated"],
              "skipped": outcome["skipped"],
              "failed": outcome["failed"], "failed_requests": outcome["failed_requests"]}
    report["furniture_exports"] = furniture_report
    report.update(_refresh_market_read_model(path))
    return report


if __name__ == "__main__":
    print(json.dumps(refresh(), indent=2))
