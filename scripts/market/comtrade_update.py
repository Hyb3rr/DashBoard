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

BILATERAL_URL = "https://comtradeapi.un.org/tools/v1/getBilateralData/C/A/HS"
MIRROR_PATH = market_refresh.MIRROR_CACHE
RETRYABLE_STATUS = {408, 429, 500, 502, 503, 504}


def _numeric_code(country: str) -> str | None:
    item = pycountry.countries.get(alpha_2=country.upper())
    return item.numeric if item else None


def _retry_delay(error: HTTPError, attempt: int) -> float:
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


def _fetch(country: str, year: int, timeout: float = 30.0) -> list[dict]:
    numeric = _numeric_code(country)
    if not numeric:
        return []
    params = {"period": str(year), "reporterCode": numeric, "cmdCode": market_refresh.HS_PARENT,
              "flowCode": "M", "partnerCode": "0", "maxRecords": "500", "format": "json",
              "includeDesc": "false"}
    api_key = os.getenv("COMTRADE_API_KEY")
    if api_key:
        params["subscription-key"] = api_key
    request = Request(f"{BILATERAL_URL}?{urlencode(params)}", headers={"User-Agent": "IPIntel-Comtrade/1.0"})
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
    return sorted(item["country_code"] for item in catalog_rows() if item["primary_market"])


def refresh(countries: list[str] | None = None, years: list[int] | None = None,
            fetcher=_fetch, path: str | Path = MIRROR_PATH, now: datetime | None = None) -> dict:
    """Refresh uncached recent observations, preserving good state on failure."""
    path = Path(path)
    current = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {"trade": {}, "provenance": {}, "checks": {}}
    trade, provenance, checks = current.get("trade") or {}, current.get("provenance") or {}, current.get("checks") or {}
    countries = countries if countries is not None else _primary_countries()
    years = years or [market_refresh.COMPLETE_YEAR - offset for offset in range(market_refresh.MAX_TRADE_AGE_YEARS + 1)]
    now = now or datetime.now(timezone.utc)
    max_age = timedelta(hours=float(os.getenv("COMTRADE_MIRROR_RECHECK_HOURS", "24")))
    updated = failed = skipped = 0
    failed_requests = []
    for country in countries:
        for year in years:
            stamp = (checks.get(country) or {}).get(str(year))
            if stamp:
                try:
                    if now - datetime.fromisoformat(stamp) < max_age:
                        skipped += 1
                        continue
                except ValueError:
                    pass
            try:
                value = _aggregate(fetcher(country, year), country, year)
            except Exception:
                failed += 1
                failed_requests.append(f"{country}:{year}")
                continue
            checks.setdefault(country, {})[str(year)] = now.isoformat()
            if value is None:
                continue
            trade.setdefault(country, {}).setdefault(market_refresh.HS_PARENT, {})[str(year)] = value
            entry = provenance.setdefault(country, {"method": "mirror", "confidence": "medium", "years": []})
            if isinstance(entry, str):
                entry = {"method": entry, "confidence": "medium", "years": []}
                provenance[country] = entry
            if str(year) not in entry.setdefault("years", []):
                entry["years"].append(str(year))
            entry["method"], entry["confidence"] = "mirror", "medium"
            updated += 1
    payload = {"schema_version": 2, "refreshed_at": now.isoformat(), "trade": trade, "provenance": provenance, "checks": checks}
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
    report = {"status": "updated", "countries": len(countries), "observations": updated, "skipped": skipped,
              "failed": failed, "failed_requests": failed_requests}
    if path == MIRROR_PATH:
        report["market_refresh"] = market_refresh.refresh()
        if os.getenv("POSTGRES_DSN"):
            from ..db.repositories import RegionRepository
            seed = json.loads(market_refresh.REGION_SEED_PATH.read_text(encoding="utf-8"))
            RegionRepository().seed(seed)
            report["read_model"] = {"status": "updated", "countries": len(seed)}
    return report


if __name__ == "__main__":
    print(json.dumps(refresh(), indent=2))
