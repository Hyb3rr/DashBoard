"""Collect province-by-industry enterprise-count evidence for Vietnam.

The collector is an explicit, rate-limited batch job. It stores the API's raw
prefix codes and response totals with provenance; it does not create a market
score, infer purchasing intent, or run from an API request handler.
"""

from __future__ import annotations

import argparse
import json
import re
import time
import unicodedata
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from urllib.error import HTTPError

from app.core.vietnam_geography import PROVINCES

ROOT = Path(__file__).resolve().parents[2]
API_ROOT = "https://doanhnghiep.vn/api/v1"
CONTRACT_PATH = ROOT / "schemas/vietnam_enterprise_source_contract.json"
DEFAULT_OUTPUT = ROOT / "data/market/vietnam_province_enrichment/province_enterprise_context.json"
TRACK_PREFIXES = {
    "woodworking": ("C16", "C31"),
    "metalworking": ("C24", "C25", "C28"),
}


def _key(value: object) -> str:
    text = str(value or "").replace("Đ", "D").replace("đ", "d")
    text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode().lower()
    return " ".join(re.sub(r"[^a-z0-9]+", " ", text).split())


def _request_json(url: str, timeout: int = 30) -> dict:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "IPIntel-VN-Enterprise-Refresh/1.0", "Accept": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def _url(path: str, **params: object) -> str:
    query = urllib.parse.urlencode(params)
    return f"{API_ROOT}/{path}{'?' + query if query else ''}"


def _province_lookup(payload: dict) -> dict[str, dict]:
    items = payload.get("items") if isinstance(payload, dict) else None
    if not isinstance(items, list):
        raise ValueError("Province reference response has no items list")
    lookup = {}
    for item in items:
        if not isinstance(item, dict) or not item.get("name_vi") or not item.get("slug"):
            continue
        key = _key(item["name_vi"])
        lookup[key] = item
        # The API uses a city prefix for the post-2025 HCMC label while the
        # canonical project catalogue stores the short administrative name.
        if key.startswith("tp "):
            lookup[key[3:]] = item
        if key.startswith("thanh pho "):
            lookup[key[10:]] = item
    return lookup


def _count_response(payload: dict) -> int | None:
    if not isinstance(payload, dict) or not isinstance(payload.get("total"), int):
        return None
    return max(0, payload["total"])


def _fetch_count(fetch: Callable[[str], dict], url: str, retries: int = 2) -> tuple[dict | None, str | None]:
    """Fetch a count, retrying transient HTTP failures without hiding status."""
    for attempt in range(retries + 1):
        try:
            return fetch(url), None
        except HTTPError as exc:
            status = int(exc.code)
            if status not in {403, 429, 500, 502, 503, 504} or attempt >= retries:
                return None, f"HTTP {status}"
            time.sleep(min(30.0, 2.0 ** attempt))
        except Exception as exc:  # noqa: BLE001 - preserve source failure
            return None, type(exc).__name__
    return None, "HTTP retry exhausted"


def collect_snapshot(
    fetch: Callable[[str], dict] = _request_json,
    province_limit: int | None = None,
    delay_seconds: float = 1.05,
    retrieved_at: str | None = None,
) -> dict:
    """Collect one complete-or-explicitly-partial snapshot.

    ``fetch`` is injectable so policy tests never call the network.
    """
    retrieved = retrieved_at or datetime.now(timezone.utc).isoformat()
    province_url = _url("provinces")
    province_payload = fetch(province_url)
    lookup = _province_lookup(province_payload)
    units = PROVINCES[:province_limit] if province_limit else PROVINCES
    records = []
    for unit in units:
        api_province = lookup.get(_key(unit["name"]))
        base = {
            "geo_unit_id": unit["code"],
            "province_name": unit["name"],
            "unit_type": unit["type"],
            "source_name": "Doanhnghiep.vn public company API",
            "source_url": province_url,
            "retrieved_at": retrieved,
            "source_geography": api_province,
            "geography_basis": "API province reference matched by normalized current province name",
            "taxonomy_version": "VSIC2018-working-1",
            "tracks": {},
        }
        if not api_province:
            for track in TRACK_PREFIXES:
                base["tracks"][track] = {"value": None, "unit": "active registered enterprises", "components": [], "limitation": "Province is absent from API reference data."}
            records.append(base)
            continue
        for track, prefixes in TRACK_PREFIXES.items():
            components = []
            for index, prefix in enumerate(prefixes):
                if index:
                    time.sleep(max(0, delay_seconds))
                query_url = _url("companies", province=api_province["slug"], industry=prefix, status="active", page=1, page_size=1)
                payload, error = _fetch_count(fetch, query_url)
                try:
                    if error:
                        raise RuntimeError(error)
                    value = _count_response(payload)
                    limitation = None if value is not None else "API response did not contain an integer total."
                    components.append({"api_filter_code": prefix, "raw_value": payload.get("total"), "value": value, "unit": "active registered enterprises", "source_url": query_url, "reference_period": "source-current", "limitation": limitation})
                except Exception as exc:  # noqa: BLE001 - preserve failed component as unknown
                    components.append({"api_filter_code": prefix, "raw_value": None, "value": None, "unit": "active registered enterprises", "source_url": query_url, "reference_period": "source-current", "limitation": f"API request failed: {type(exc).__name__}"})
            values = [item["value"] for item in components]
            complete = all(value is not None for value in values)
            base["tracks"][track] = {
                "value": sum(values) if complete else None,
                "unit": "active registered enterprises",
                "components": components,
                "source_name": "Doanhnghiep.vn public company API",
                "source_url": "https://doanhnghiep.vn/api/docs",
                "reference_period": "source-current",
                "retrieved_at": retrieved,
                "raw_value": [item["raw_value"] for item in components],
                "transformation_method": "sum of disjoint VSIC API prefix totals" if complete else None,
                "confidence": "medium" if complete else "unknown",
                "limitation": None if complete else "At least one target prefix is unknown; aggregate withheld.",
            }
        records.append(base)
    return {
        "schema_version": "vn-province-enterprise-context-1",
        "scope": "VN",
        "retrieved_at": retrieved,
        "source": {"source_name": "Doanhnghiep.vn public company API", "source_url": "https://doanhnghiep.vn/api/docs", "api_version": "v1", "rate_limit": "60 requests/minute/IP"},
        "taxonomy_version": "VSIC2018-working-1",
        "records": records,
        "complete": len(records) == len(PROVINCES) and all(all(track.get("value") is not None for track in row["tracks"].values()) for row in records),
        "limitations": ["This is a registry-derived proxy, not an official NSO enterprise count.", "The API documentation does not state its underlying VSIC revision; raw API prefixes are preserved.", "No density, score or purchase-intent inference is calculated."],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--province-limit", type=int)
    parser.add_argument("--delay", type=float, default=1.05)
    args = parser.parse_args()
    snapshot = collect_snapshot(province_limit=args.province_limit, delay_seconds=args.delay)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(snapshot, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"output": str(args.output), "records": len(snapshot["records"]), "complete": snapshot["complete"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
