"""One hourly, failure-isolated runner for due data updates.

Intelligence refresh ownership lives here, never in FastAPI startup.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import math
import os
import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.config.settings import DATA_DIR
from app.services.profiles import refresh_due_profiles
from scripts.ops.tor_refresh import refresh_tor_exit_list
from scripts.market.worldbank_update import update_world_bank
from scripts.market.comtrade_update import refresh as refresh_comtrade_mirror
from scripts.market.country_sources import refresh_country_sources
from scripts.market.country_product_prior import refresh as refresh_country_prior
from app.services.industrial_demand import refresh as refresh_industrial_demand
from app.services.city_overall_snapshot import publish_vietnam_snapshot
from app.services.country_demand import CountryDemandService
from app.services.retention_cleanup import (
    run_change_log_retention,
    run_once as run_retention_cleanup,
)
from scripts.geo.geography_foundation import refresh_all as refresh_geography
from scripts.geo.osm_h3_pilot import refresh_osm_pilot
from scripts.geo.local_evidence_refresh import refresh_local_evidence
from scripts.geo.local_opportunity_refresh import refresh_local_opportunity
from scripts.geo.area_membership_refresh import refresh_area_membership
from scripts.geo.overlap_refresh import refresh_overlap
from app.core.intel_updater import run_due_sources
from app.db.market_repository import MarketRepository
from app.db import postgres

STATE_PATH = DATA_DIR / "update_state.json"
LOCK_PATH = DATA_DIR / "data_scheduler.lock"


def connect():
    """Stub — kept for test monkeypatching compatibility. No SQLite in production."""
    raise RuntimeError("No database connection in scheduler; use PostgreSQL directly")



def _due(item: dict, now: datetime) -> bool:
    """Return whether a task's configured interval has elapsed."""
    stamp = item.get("last_checked_at")
    if not stamp:
        return True
    try:
        checked = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except ValueError:
        return True
    if item.get("interval_seconds"):
        interval = timedelta(seconds=float(item["interval_seconds"]))
    else:
        interval = timedelta(hours=float(item.get("interval_hours", 0))) if item.get("interval_hours") else timedelta(days=float(item.get("interval_days", 0)))
    return now - checked >= interval


def _load(path: Path) -> dict:
    """Load scheduler state and fall back to an empty mapping when invalid."""
    try:
        value = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _setting_enabled(name: str, default: str = "false") -> bool:
    """Interpret a scheduler environment flag using the accepted truthy values."""
    return os.getenv(name, default).strip().lower() in {"1", "true", "yes", "on"}


def _positive_hours(name: str, default: float) -> float:
    """Read a finite positive refresh cadence bounded to one year."""
    try:
        value = float(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default
    if not math.isfinite(value) or value <= 0:
        return default
    return min(value, 24 * 365)


def _run_due_refresh(
    name: str,
    state: dict,
    report: dict,
    now: datetime,
    refresh,
    *,
    interval_key: str = "interval_days",
    interval_value: float = 30,
    replace_interval: bool = False,
    success_statuses: tuple[str, ...] = ("updated",),
    include_error_message: bool = True,
    error_message_limit: int | None = 240,
) -> dict | None:
    """Run one interval-gated refresh and persist its status timestamps."""
    item = state.setdefault(name, {})
    if replace_interval:
        item[interval_key] = interval_value
    else:
        item.setdefault(interval_key, interval_value)
    if not _due(item, now):
        report[name] = {"status": "not_due"}
        return None
    item["last_checked_at"] = now.isoformat()
    try:
        result = refresh()
    except Exception as exc:
        result = {"status": "failed", "error": type(exc).__name__}
        if include_error_message:
            message = str(exc)
            result["message"] = message if error_message_limit is None else message[:error_message_limit]
    report[name] = result
    item["status"] = result.get("status", "failed")
    if result.get("status") in success_statuses:
        item["last_success_at"] = now.isoformat()
    return result


def _run_optional_task(report: dict, name: str, flag: str, task, *, default: str = "false", include_error_message: bool = True) -> None:
    """Run an environment-enabled task and isolate its failure in the report."""
    if not _setting_enabled(flag, default):
        return
    try:
        report[name] = task()
    except Exception as exc:
        result = {"status": "failed", "error": type(exc).__name__}
        if include_error_message:
            result["message"] = str(exc)[:240]
        report[name] = result


def _refresh_comtrade_bundle() -> dict:
    """Refresh the Comtrade mirror and its dependent country prior when changed."""
    result = refresh_comtrade_mirror()
    if result.get("furniture_exports", {}).get("updated", 0):
        try:
            result["country_prior"] = refresh_country_prior()
        except Exception as exc:
            result["country_prior"] = {"status": "failed", "error": type(exc).__name__}
    return result


def _refresh_market_sources_bundle(now: datetime) -> dict:
    """Refresh country sources and rebuild the prior after successful source updates."""
    source_result = refresh_country_sources(DATA_DIR / "market_sources", now=now)
    result = {"sources": source_result}
    if source_result.get("status") in {"updated", "partial"}:
        result["country_prior"] = refresh_country_prior()
        result["status"] = result["country_prior"].get("status", "updated")
    else:
        result["status"] = source_result.get("status", "failed")
    return result


def _refresh_country_demand_bundle(now: datetime) -> dict:
    """Refresh all country-demand periods and report partial publication status."""
    service, repository = CountryDemandService(), MarketRepository()
    periods = {}
    for period in ("7d", "30d", "90d"):
        try:
            periods[period] = service.refresh(repository, now=now, period=period)
        except Exception as exc:
            periods[period] = {"status": "failed", "error": type(exc).__name__, "message": str(exc)[:240]}
    published = any(result.get("status") == "published" for result in periods.values())
    failed = any(result.get("status") == "failed" for result in periods.values())
    status = "failed" if failed and not published else "published" if published else "no_data"
    return {"status": status, "periods": periods}


def _run_primary_sources(state: dict, report: dict, now: datetime) -> None:
    """Run the hourly Tor and periodic World Bank source refreshes."""
    _run_due_refresh(
        "tor", state, report, now, refresh_tor_exit_list,
        interval_key="interval_hours",
        interval_value=float(os.getenv("TOR_EXIT_LIST_REFRESH_HOURS", "1")),
        replace_interval=True,
        success_statuses=("updated", "not_modified"),
        error_message_limit=None,
    )
    _run_due_refresh(
        "world_bank", state, report, now, update_world_bank,
        interval_value=30,
        success_statuses=("updated", "not_modified"),
        error_message_limit=None,
    )


def _run_market_sources(state: dict, report: dict, now: datetime) -> None:
    """Run enabled trade, national-source, industrial, city, and country-demand jobs."""
    if _setting_enabled("COMTRADE_MIRROR_REFRESH"):
        _run_due_refresh("comtrade_mirror", state, report, now, _refresh_comtrade_bundle,
                         interval_value=1, success_statuses=("updated",), error_message_limit=None)
    if _setting_enabled("MARKET_SOURCES_REFRESH"):
        _run_due_refresh("market_sources", state, report, now, lambda: _refresh_market_sources_bundle(now),
                         interval_value=float(os.getenv("MARKET_SOURCES_REFRESH_DAYS", "30")),
                         success_statuses=("updated", "partial", "completed"))
    if _setting_enabled("INDUSTRIAL_DEMAND_REFRESH"):
        _run_due_refresh("industrial_demand", state, report, now,
                         lambda: refresh_industrial_demand(MarketRepository(), country_code="VN", now=now),
                         interval_value=float(os.getenv("INDUSTRIAL_DEMAND_REFRESH_DAYS", "30")),
                         success_statuses=("published",))
    if _setting_enabled("CITY_OVERALL_REFRESH", "true"):
        _run_due_refresh("city_overall", state, report, now,
                         lambda: publish_vietnam_snapshot(MarketRepository(), now=now),
                         interval_value=1, success_statuses=("published",))
    if _setting_enabled("COUNTRY_DEMAND_REFRESH", "true"):
        _run_due_refresh("country_demand", state, report, now,
                         lambda: _refresh_country_demand_bundle(now),
                         interval_value=1, success_statuses=("published",))


def _run_geography_jobs(state: dict, report: dict, now: datetime) -> None:
    """Run scheduled geography refresh and enabled OSM-derived local evidence jobs."""
    if _setting_enabled("GEOGRAPHY_REFRESH"):
        item = state.setdefault("geography", {})
        item.setdefault("interval_days", 30)
        global_url = os.getenv("GHSL_CITY_GLOBAL_URL")
        if _due(item, now) and global_url:
            _run_due_refresh("geography", state, report, now,
                             lambda: refresh_geography(MarketRepository(), global_url),
                             interval_value=30, success_statuses=("completed", "partial"),
                             include_error_message=False)
    optional_jobs = (
        ("osm", "OSM_REFRESH", lambda: refresh_osm_pilot(MarketRepository())),
        ("osm_auxiliary", "OSM_AUXILIARY_REFRESH", lambda: refresh_local_evidence(MarketRepository())),
        ("local_opportunity", "LOCAL_OPPORTUNITY_REFRESH", lambda: refresh_local_opportunity(MarketRepository())),
        ("area_membership", "AREA_MEMBERSHIP_REFRESH", lambda: refresh_area_membership(MarketRepository())),
        ("overlap", "LOCAL_OVERLAP_REFRESH", lambda: refresh_overlap(MarketRepository())),
    )
    for name, flag, task in optional_jobs:
        _run_optional_task(report, name, flag, task)


def _run_background_jobs(report: dict, now: datetime) -> None:
    """Run enabled privacy, intelligence, and retention maintenance tasks."""
    _run_optional_task(
        report, "privacy", "PRIVACY_REFRESH_SCHEDULER",
        lambda: asyncio.run(refresh_due_profiles(None, limit=int(os.getenv("PRIVACY_REFRESH_BATCH", "100")), now=now)),
        default="true", include_error_message=False,
    )
    _run_optional_task(report, "intel", "INTEL_UPDATER_ENABLED", lambda: run_due_sources(now), include_error_message=False)
    _run_optional_task(
        report, "change_log_retention", "CHANGE_LOG_RETENTION_ENABLED",
        run_change_log_retention, default="true",
    )
    _run_optional_task(report, "retention", "RETENTION_CLEANUP_ENABLED", lambda: run_retention_cleanup(now=now))


def _refresh_sapics() -> dict:
    """Refresh local SAPICS assets when the shared intel updater is disabled."""
    from app.services.sapics_updater import refresh
    return refresh()


def _refresh_ip2region() -> dict:
    """Refresh local ip2region databases from their validated upstream files."""
    from app.services.ip2region_updater import refresh
    return refresh()


def _run_local_geo_database_updates(state: dict, report: dict, now: datetime) -> None:
    """Schedule local GeoIP database refreshes without blocking app startup."""
    intel_enabled = _setting_enabled("INTEL_UPDATER_ENABLED")
    shared_default = os.getenv("INTEL_UPDATER_ENABLED", "false")
    if not intel_enabled and _setting_enabled("SAPICS_UPDATER_ENABLED", shared_default):
        _run_due_refresh(
            "sapics_local", state, report, now, _refresh_sapics,
            interval_key="interval_hours",
            interval_value=_positive_hours("SAPICS_REFRESH_HOURS", 24),
            replace_interval=True,
            success_statuses=("ok", "partial"),
            include_error_message=False,
        )
    if _setting_enabled("IP2REGION_UPDATER_ENABLED", shared_default):
        _run_due_refresh(
            "ip2region", state, report, now, _refresh_ip2region,
            interval_key="interval_hours",
            interval_value=_positive_hours("IP2REGION_REFRESH_HOURS", 24),
            replace_interval=True,
            success_statuses=("ok", "partial"),
            include_error_message=False,
        )


def _save_state(path: Path, state: dict, now: datetime) -> None:
    """Atomically persist scheduler state after all independent tasks finish."""
    state["last_run_at"] = now.isoformat()
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def run_scheduler(state_path: str | Path = STATE_PATH, lock_path: str | Path = LOCK_PATH, now: datetime | None = None) -> dict:
    """Run due refresh jobs under one process lock and persist their outcomes."""
    state_path, lock_path = Path(state_path), Path(lock_path)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("w") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {"status": "locked"}
        now = now or datetime.now(timezone.utc)
        state, report = _load(state_path), {}
        _run_primary_sources(state, report, now)
        _run_local_geo_database_updates(state, report, now)
        _run_market_sources(state, report, now)
        _run_geography_jobs(state, report, now)
        _run_background_jobs(report, now)
        _save_state(state_path, state, now)
        result = {"status": "completed", "tasks": report}
        postgres.close_pool()
        return result


def main() -> int:
    """Parse CLI paths, execute one scheduler pass, and print its report."""
    parser = argparse.ArgumentParser(description="Run due data refresh tasks")
    parser.add_argument("--state", default=str(STATE_PATH))
    parser.add_argument("--lock", default=str(LOCK_PATH))
    args = parser.parse_args()
    print(json.dumps(run_scheduler(args.state, args.lock), indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
