"""Replay a compressed raw-log chunk through the isolated pure normalizer."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

from app.core.logs import import_apache_lines


class RawReplayError(RuntimeError):
    pass


def replay_zstd(path: str | Path, source: str) -> dict:
    """Stream a zstd chunk and normalize it without database side effects."""
    archive = Path(path)
    if not archive.is_file() or archive.suffix != ".zst":
        raise RawReplayError("replay input must be an existing .zst file")
    zstd = shutil.which("zstd")
    if not zstd:
        raise RawReplayError("zstd executable is unavailable; replay stopped")
    process = subprocess.Popen([zstd, "-q", "-d", "-c", str(archive)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    digest = hashlib.sha256()
    raw_bytes = 0
    raw_lines = 0

    def line_stream():
        nonlocal raw_bytes, raw_lines
        assert process.stdout
        for line in process.stdout:
            digest.update(line)
            raw_bytes += len(line)
            raw_lines += 1
            yield line.decode("utf-8")

    try:
        normalized = import_apache_lines(line_stream(), source)
        code = process.wait()
        if code:
            error = process.stderr.read().decode("utf-8", "replace") if process.stderr else ""
            raise RawReplayError(f"zstd replay failed with exit {code}: {error[-240:]}")
        return {
            "source": source, "archive": str(archive), "raw_lines": raw_lines,
            "raw_bytes": raw_bytes, "raw_sha256": digest.hexdigest(),
            "parsed_events": normalized["parsed"], "skipped_lines": normalized["skipped"],
            "database_writes": 0, "status": "validated",
        }
    except Exception:
        if process.poll() is None:
            process.kill()
        process.wait()
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description="Replay one compressed raw-log archive in isolation")
    parser.add_argument("archive", type=Path)
    parser.add_argument("--source", default="raw-archive-replay")
    args = parser.parse_args()
    print(json.dumps(replay_zstd(args.archive, args.source), indent=2))


if __name__ == "__main__":
    main()
