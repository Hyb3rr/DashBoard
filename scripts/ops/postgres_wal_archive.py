"""Archive one completed PostgreSQL WAL file into the local PITR spool."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import sys
import tempfile


ROOT_DIR = Path(__file__).resolve().parents[2]
DEFAULT_SPOOL_DIR = ROOT_DIR / "data" / "postgres-wal-spool"
CHUNK_SIZE = 1024 * 1024


def _spool_dir() -> Path:
    return Path(os.getenv("POSTGRES_WAL_SPOOL_DIR", str(DEFAULT_SPOOL_DIR))).resolve()


def _minimum_free_bytes() -> int:
    try:
        gib = float(os.getenv("POSTGRES_WAL_SPOOL_MIN_FREE_GIB", "10"))
    except ValueError as exc:
        raise RuntimeError("POSTGRES_WAL_SPOOL_MIN_FREE_GIB must be numeric") from exc
    if gib < 0:
        raise RuntimeError("POSTGRES_WAL_SPOOL_MIN_FREE_GIB must not be negative")
    return int(gib * 1024 ** 3)


def _digest(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        while chunk := source.read(CHUNK_SIZE):
            digest.update(chunk)
            size += len(chunk)
    return size, digest.hexdigest()


def archive_wal(source_path: str | Path, wal_name: str | None = None,
                spool_dir: str | Path | None = None) -> dict:
    """Atomically copy a completed WAL file; return its size and SHA-256."""
    source = Path(source_path).resolve()
    name = wal_name or source.name
    if not name or Path(name).name != name:
        raise RuntimeError("WAL name must be a plain filename")
    if not source.is_file():
        raise RuntimeError(f"WAL source is not a regular file: {source}")

    spool = Path(spool_dir).resolve() if spool_dir else _spool_dir()
    spool.mkdir(parents=True, exist_ok=True)
    if shutil.disk_usage(spool).free < _minimum_free_bytes():
        raise RuntimeError(f"WAL spool free disk is below safety floor: {spool}")
    destination = spool / name
    if destination.is_symlink():
        raise RuntimeError(f"WAL spool destination is a symlink: {destination}")

    source_size = source.stat().st_size
    digest = hashlib.sha256()
    copied = 0
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", prefix=f".{name}.", suffix=".part", dir=spool, delete=False) as target:
            temporary = Path(target.name)
            with source.open("rb") as source_stream:
                while chunk := source_stream.read(CHUNK_SIZE):
                    target.write(chunk)
                    digest.update(chunk)
                    copied += len(chunk)
            target.flush()
            os.fsync(target.fileno())
        if copied != source_size or source.stat().st_size != source_size:
            raise RuntimeError(f"WAL source changed during archive: {source}")
        digest_hex = digest.hexdigest()

        if destination.exists():
            existing_size, existing_digest = _digest(destination)
            if (existing_size, existing_digest) == (copied, digest_hex):
                return {"wal_name": name, "bytes": copied, "sha256": digest_hex, "status": "already_archived"}
            raise RuntimeError(f"conflicting WAL already exists in spool: {destination}")

        os.chmod(temporary, 0o600)
        try:
            os.link(temporary, destination)
        except FileExistsError:
            existing_size, existing_digest = _digest(destination)
            if (existing_size, existing_digest) != (copied, digest_hex):
                raise RuntimeError(f"conflicting WAL already exists in spool: {destination}")
            return {"wal_name": name, "bytes": copied, "sha256": digest_hex, "status": "already_archived"}
        return {"wal_name": name, "bytes": copied, "sha256": digest_hex, "status": "archived"}
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(argv: list[str]) -> int:
    if len(argv) not in (2, 3):
        print("usage: postgres_wal_archive.py SOURCE_PATH [WAL_NAME]", file=sys.stderr)
        return 2
    try:
        print(archive_wal(argv[1], argv[2] if len(argv) == 3 else None))
        return 0
    except Exception as exc:
        print(f"WAL archive failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
