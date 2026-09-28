"""Compatibility entry point for the cross-platform archive job."""

from __future__ import annotations

import argparse
from pathlib import Path

from scripts.ops.raw_log_archive_job import DEFAULT_SPOOL_DIR, RawLogArchive, run_once as _run_once


def run_once(spool_dir: str | Path = DEFAULT_SPOOL_DIR,
             lock_path: str | Path | None = None) -> dict:
    """Run one locked archive maintenance cycle through the shared job."""
    return _run_once(spool_dir, lock_path, archive_factory=RawLogArchive)


def main() -> int:
    """Parse archive scheduler options and print the one-shot result."""
    parser = argparse.ArgumentParser(description="Drain raw archive artifacts once")
    parser.add_argument("--spool-dir", default=str(DEFAULT_SPOOL_DIR))
    parser.add_argument("--lock")
    args = parser.parse_args()
    import json
    print(json.dumps(run_once(args.spool_dir, args.lock), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
