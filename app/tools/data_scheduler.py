"""One hourly, failure-isolated runner for due data updates."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ..config.settings import DATA_DIR
from ..core.db import connect
from ..core.buckets import trim_buckets
from ..services.profiles import refresh_due_profiles
from .tor_refresh import refresh_tor_exit_list
from .worldbank_update import update_world_bank
from ..core.intel_updater import run_due_sources

STATE_PATH = DATA_DIR / "update_state.json"
LOCK_PATH = DATA_DIR / "data_scheduler.lock"


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
            item.setdefault("interval_hours" if name == "tor" else "interval_days", 6 if name == "tor" else 30)
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
        if os.getenv("PRIVACY_REFRESH_SCHEDULER", "true").strip().lower() in {"1", "true", "yes", "on"}:
            try:
                conn = connect()
                try:
                    report["privacy"] = asyncio.run(refresh_due_profiles(conn, limit=int(os.getenv("PRIVACY_REFRESH_BATCH", "100")), now=now))
                finally:
                    conn.close()
            except Exception as exc:
                report["privacy"] = {"status": "failed", "error": type(exc).__name__}
        trim_state = state.setdefault("bucket_trim", {})
        trim_state.setdefault("interval_seconds", int(os.getenv("BUCKET_TRIM_INTERVAL_SECONDS", "1800")))
        if _due(trim_state, now):
            trim_state["last_checked_at"] = now.isoformat()
            try:
                conn = connect()
                try:
                    deleted = trim_buckets(conn)
                    conn.commit()
                    report["bucket_trim"] = {"status": "updated", "deleted": deleted}
                finally:
                    conn.close()
            except Exception as exc:
                report["bucket_trim"] = {"status": "failed", "error": type(exc).__name__}
        else:
            report["bucket_trim"] = {"status": "not_due"}
        if os.getenv("INTEL_UPDATER_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"}:
            try:
                report["intel"] = run_due_sources(now)
            except Exception as exc:
                report["intel"] = {"status": "failed", "error": type(exc).__name__}
        state["last_run_at"] = now.isoformat()
        temporary = state_path.with_name(f".{state_path.name}.tmp")
        temporary.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        os.replace(temporary, state_path)
        return {"status": "completed", "tasks": report}


def main() -> int:
    parser = argparse.ArgumentParser(description="Run due data refresh tasks")
    parser.add_argument("--state", default=str(STATE_PATH))
    parser.add_argument("--lock", default=str(LOCK_PATH))
    args = parser.parse_args()
    print(json.dumps(run_scheduler(args.state, args.lock), indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
