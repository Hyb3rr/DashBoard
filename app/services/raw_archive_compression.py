"""Lossless compression operations for sealed raw archive chunks."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess


class RawArchiveCompressionError(RuntimeError):
    """Signal compression or lossless verification failure."""


def compress_and_verify(path: Path) -> dict:
    """Compress a sealed chunk and verify its checksum and line content."""
    zstd = shutil.which("zstd")
    if not zstd:
        raise RawArchiveCompressionError("zstd executable is unavailable")
    compressed = path.with_suffix(".log.zst")
    temporary = path.with_suffix(".log.zst.tmp")
    try:
        result = subprocess.run(
            [zstd, "-q", "-3", "-f", str(path), "-o", str(temporary)],
            capture_output=True, text=True, check=False,
        )
        if result.returncode:
            raise RawArchiveCompressionError(f"zstd failed with exit {result.returncode}")
        original_digest = hashlib.sha256()
        compressed_digest = hashlib.sha256()
        original_size = compressed_size = 0
        with path.open("rb") as original, temporary.open("rb") as encoded:
            while chunk := original.read(1024 * 1024):
                original_digest.update(chunk)
                original_size += len(chunk)
            while chunk := encoded.read(1024 * 1024):
                compressed_digest.update(chunk)
                compressed_size += len(chunk)
        process = subprocess.Popen(
            [zstd, "-q", "-d", "-c", str(temporary)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        verified_size = 0
        with path.open("rb") as original:
            assert process.stdout
            while expected := original.read(1024 * 1024):
                actual = process.stdout.read(len(expected))
                if actual != expected:
                    process.kill()
                    process.wait()
                    raise RawArchiveCompressionError("zstd decompression differs from original")
                verified_size += len(actual)
            trailing = process.stdout.read(1)
        code = process.wait()
        if trailing or code or verified_size != original_size:
            raise RawArchiveCompressionError("zstd decompression verification failed")
        temporary.replace(compressed)
        path.unlink()
        return {
            "original_bytes": original_size,
            "compressed_bytes": compressed_size,
            "original_sha256": original_digest.hexdigest(),
            "compressed_sha256": compressed_digest.hexdigest(),
            "compressed_path": str(compressed),
        }
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def write_compression_marker(path: Path, result: dict, source_id: str) -> None:
    """Persist verified compression metadata beside the compressed chunk."""
    compressed = path.with_suffix(".log.zst")
    marker = compressed.with_name(compressed.name + ".json")
    original_metadata = {}
    metadata_path = path.with_suffix(".json")
    if metadata_path.exists():
        original_metadata = json.loads(metadata_path.read_text())
    marker.write_text(json.dumps({
        "source": source_id, "chunk_id": path.stem,
        "started_at": original_metadata.get("started_at"),
        "ended_at": original_metadata.get("ended_at"),
        "line_count": original_metadata.get("line_count"),
        "original_path": str(path), **result, "status": "VERIFIED",
    }, indent=2) + "\n")
