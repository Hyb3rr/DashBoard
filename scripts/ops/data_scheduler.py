"""One hourly, failure-isolated runner for due data updates.

Intelligence refresh ownership lives here, never in FastAPI startup.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.config.settings import DATA_DIR
from app.services.profiles import refresh_due_profiles
from scripts.ops.tor_refresh import refresh_tor_exit_list
from scripts.market.worldbank_update import update_world_bank
from scripts.market.comtrade_update import refresh as refresh_comtrade_mirror
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
    try:
        value = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def run_scheduler(state_path: str | Path = STATE_PATH, lock_path: str | Path = LOCK_PATH, now: datetime | None = None) -> dict:
    state_path, lock_path = Path(state_path), Path(lock_path)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("w") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {"status": "locked"}
        now = now or datetime.now(timezone.utc)
        state = _load(state_path)
        report = {}
        for name, task in (("tor", refresh_tor_exit_list), ("world_bank", update_world_bank)):
            item = state.setdefault(name, {})
            if name == "tor":
                item["interval_hours"] = float(os.getenv("TOR_EXIT_LIST_REFRESH_HOURS", "1"))
            else:
                item.setdefault("interval_days", 30)
            if not _due(item, now):
                report[name] = {"status": "not_due"}
                continue
            item["last_checked_at"] = now.isoformat()
            try:
                result = task()
            except Exception as exc:
                result = {"status": "failed", "error": type(exc).__name__, "message": str(exc)}
            report[name] = result
            item["status"] = result.get("status", "failed")
            if result.get("status") in {"updated", "not_modified"}:
                item["last_success_at"] = now.isoformat()
        if os.getenv("COMTRADE_MIRROR_REFRESH", "false").strip().lower() in {"1", "true", "yes", "on"}:
            item = state.setdefault("comtrade_mirror", {})
            item.setdefault("interval_days", 1)
            if _due(item, now):
                item["last_checked_at"] = now.isoformat()
                try:
                    result = refresh_comtrade_mirror()
                except Exception as exc:
                    result = {"status": "failed", "error": type(exc).__name__, "message": str(exc)}
                report["comtrade_mirror"] = result
                item["status"] = result.get("status", "failed")
                if result.get("status") == "updated":
                    item["last_success_at"] = now.isoformat()
        if os.getenv("GEOGRAPHY_REFRESH", "false").strip().lower() in {"1", "true", "yes", "on"}:
            item = state.setdefault("geography", {})
            item.setdefault("interval_days", 30)
            global_url = os.getenv("GHSL_CITY_GLOBAL_URL")
            if _due(item, now) and global_url:
                item["last_checked_at"] = now.isoformat()
                try:
                    result = refresh_geography(MarketRepository(), global_url)
                except Exception as exc:
                    result = {"status": "failed", "error": type(exc).__name__}
                report["geography"] = result
                item["status"] = result.get("status", "failed")
                if result.get("status") in {"completed", "partial"}:
                    item["last_success_at"] = now.isoformat()
        if os.getenv("OSM_REFRESH", "false").strip().lower() in {"1", "true", "yes", "on"}:
            try:
                report["osm"] = refresh_osm_pilot(MarketRepository())
            except Exception as exc:
                report["osm"] = {"status": "failed", "error": type(exc).__name__, "message": str(exc)[:240]}
        if os.getenv("OSM_AUXILIARY_REFRESH", "false").strip().lower() in {"1", "true", "yes", "on"}:
            try:
                report["osm_auxiliary"] = refresh_local_evidence(MarketRepository())
            except Exception as exc:
                report["osm_auxiliary"] = {"status": "failed", "error": type(exc).__name__, "message": str(exc)[:240]}
        if os.getenv("LOCAL_OPPORTUNITY_REFRESH", "false").strip().lower() in {"1", "true", "yes", "on"}:
            try:
                report["local_opportunity"] = refresh_local_opportunity(MarketRepository())
            except Exception as exc:
                report["local_opportunity"] = {"status": "failed", "error": type(exc).__name__, "message": str(exc)[:240]}
        if os.getenv("AREA_MEMBERSHIP_REFRESH", "false").strip().lower() in {"1", "true", "yes", "on"}:
            try:
                report["area_membership"] = refresh_area_membership(MarketRepository())
            except Exception as exc:
                report["area_membership"] = {"status": "failed", "error": type(exc).__name__, "message": str(exc)[:240]}
        if os.getenv("LOCAL_OVERLAP_REFRESH", "false").strip().lower() in {"1", "true", "yes", "on"}:
            try:
                report["overlap"] = refresh_overlap(MarketRepository())
            except Exception as exc:
                report["overlap"] = {"status": "failed", "error": type(exc).__name__, "message": str(exc)[:240]}
        if os.getenv("PRIVACY_REFRESH_SCHEDULER", "true").strip().lower() in {"1", "true", "yes", "on"}:
            try:
                report["privacy"] = asyncio.run(refresh_due_profiles(None, limit=int(os.getenv("PRIVACY_REFRESH_BATCH", "100")), now=now))
            except Exception as exc:
                report["privacy"] = {"status": "failed", "error": type(exc).__name__}
        if os.getenv("INTEL_UPDATER_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"}:
            try:
                report["intel"] = run_due_sources(now)
            except Exception as exc:
                report["intel"] = {"status": "failed", "error": type(exc).__name__}
        state["last_run_at"] = now.isoformat()
        temporary = state_path.with_name(f".{state_path.name}.tmp")
        temporary.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        os.replace(temporary, state_path)
        result = {"status": "completed", "tasks": report}
        postgres.close_pool()
        return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Run due data refresh tasks")
    parser.add_argument("--state", default=str(STATE_PATH))
    parser.add_argument("--lock", default=str(LOCK_PATH))
    args = parser.parse_args()
    print(json.dumps(run_scheduler(args.state, args.lock), indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
