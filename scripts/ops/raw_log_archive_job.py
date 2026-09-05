"""Cross-platform, single-run raw archive maintenance job."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
from typing import Callable

from app.services.raw_log_archive import DEFAULT_SPOOL_DIR, RawLogArchive


class RunLock:
    """Small cross-platform process lock using atomic directory creation."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.acquired = False

    def acquire(self) -> bool:
        try:
            self.path.mkdir(parents=True)
        except FileExistsError:
            owner = self.path / "owner"
            try:
                pid = int(owner.read_text(encoding="ascii").strip())
            except (FileNotFoundError, ValueError):
                return False
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                try:
                    owner.unlink(missing_ok=True)
                    self.path.rmdir()
                except OSError:
                    return False
                return self.acquire()
            except PermissionError:
                return False
            return False
        (self.path / "owner").write_text(str(os.getpid()), encoding="ascii")
        self.acquired = True
        return True

    def release(self) -> None:
        if not self.acquired:
            return
        try:
            (self.path / "owner").unlink(missing_ok=True)
            self.path.rmdir()
        except FileNotFoundError:
            pass
        finally:
            self.acquired = False

    def __enter__(self) -> "RunLock":
        if not self.acquire():
            raise RuntimeError("raw archive maintenance already running")
        return self

    def __exit__(self, *_: object) -> None:
        self.release()


def run_once(
    spool_dir: str | Path = DEFAULT_SPOOL_DIR,
    lock_path: str | Path | None = None,
    archive_factory: Callable[..., RawLogArchive] = RawLogArchive,
) -> dict:
    spool = Path(spool_dir)
    lock = RunLock(lock_path or spool / ".raw-archive-job.lock")
    if not lock.acquire():
        return {"status": "locked"}
    try:
        result = asyncio.run(archive_factory("scheduled", spool).maintenance_once())
        result["status"] = "completed"
        return result
    finally:
        lock.release()


def main() -> int:
    parser = argparse.ArgumentParser(description="Drain raw archive artifacts once")
    parser.add_argument("--spool-dir", default=str(DEFAULT_SPOOL_DIR))
    parser.add_argument("--lock")
    args = parser.parse_args()
    print(json.dumps(run_once(args.spool_dir, args.lock), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
