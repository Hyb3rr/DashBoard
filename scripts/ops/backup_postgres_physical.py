"""Stream a PostgreSQL physical base backup to Azure Blob."""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
import re
import subprocess
import threading
import uuid

from app.config.backup import BackupSettings
from scripts.ops.backup_clickhouse import _verify_remote_blob
from scripts.ops.backup_postgres import AzureBlobUploader, _block_id, _credential


BASE_STREAM_CHUNK = 8 * 1024 * 1024
_LSN_RE = re.compile(r"(?:start|stop) point:\s*([0-9A-F]+/[0-9A-F]+)", re.IGNORECASE)


class PhysicalBackupError(RuntimeError):
    pass


def basebackup_command(dsn: str, command: str = "pg_basebackup") -> list[str]:
    """Return a stdout tar stream; WAL is supplied by the archive chain."""
    return [
        command, "--dbname", dsn, "--pgdata=-", "--format=tar",
        "--wal-method=none", "--gzip", "--compress=3",
        "--manifest-checksums=SHA256", "--no-slot",
    ]


def _read_stderr(stream, result: list[str]) -> None:
    result.append(stream.read().decode("utf-8", "replace"))


def _observed_lsn(stderr: str, label: str) -> str | None:
    matches = re.findall(rf"{label} point:\s*([0-9A-F]+/[0-9A-F]+)", stderr, re.IGNORECASE)
    return matches[-1] if matches else None


def backup_postgres_physical(settings: BackupSettings | None = None,
                             dsn: str | None = None, backup_command: str = "pg_basebackup",
                             uploader=None, verifier=None, backup_id: str | None = None,
                             chunk_size: int = BASE_STREAM_CHUNK) -> dict:
    settings = settings or BackupSettings.from_env()
    dsn = dsn or os.getenv("POSTGRES_DSN")
    if not dsn:
        raise RuntimeError("POSTGRES_DSN is required")
    if chunk_size <= 0:
        raise ValueError("physical backup chunk size must be positive")
    backup_id = backup_id or str(uuid.uuid4())
    created_at = datetime.now(timezone.utc)
    object_key = f"{settings.prefix}/postgres-pitr/base/{backup_id}/base.tar.gz"
    manifest_key = f"{settings.prefix}/postgres-pitr/manifests/base/{backup_id}.json"
    process = subprocess.Popen(
        basebackup_command(dsn, backup_command),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    stderr_result: list[str] = []
    stderr_thread = threading.Thread(target=_read_stderr, args=(process.stderr, stderr_result), daemon=True)
    stderr_thread.start()
    uploader = uploader or AzureBlobUploader(settings)
    block_ids: list[str] = []
    digest = hashlib.sha256()
    size = 0
    buffer = bytearray()
    try:
        assert process.stdout
        while chunk := process.stdout.read(chunk_size):
            digest.update(chunk)
            size += len(chunk)
            buffer.extend(chunk)
            while len(buffer) >= settings.part_size:
                block_id = _block_id(len(block_ids) + 1)
                uploader.put_block(object_key, block_id, bytes(buffer[:settings.part_size]))
                del buffer[:settings.part_size]
                block_ids.append(block_id)
        code = process.wait()
        stderr_thread.join(timeout=5)
        if code:
            raise PhysicalBackupError(f"pg_basebackup failed with exit {code}: {stderr_result[0][-500:]}")
        if buffer or not block_ids:
            payload = bytes(buffer)
            if not payload:
                raise PhysicalBackupError("physical base backup stream is empty")
            block_id = _block_id(len(block_ids) + 1)
            uploader.put_block(object_key, block_id, payload)
            block_ids.append(block_id)
        uploader.put_block_list(object_key, block_ids)
        remote_size, remote_digest = (verifier or _verify_remote_blob)(settings, object_key)
        local_digest = digest.hexdigest()
        if remote_size != size:
            raise PhysicalBackupError("remote physical backup size verification failed")
        if remote_digest != local_digest:
            raise PhysicalBackupError("remote physical backup SHA-256 verification failed")
        completed_at = datetime.now(timezone.utc)
        stderr = stderr_result[0] if stderr_result else ""
        manifest = {
            "schema_version": 1,
            "backup_id": backup_id,
            "backup_type": "postgresql_physical_base",
            "created_at": created_at.isoformat(),
            "completed_at": completed_at.isoformat(),
            "source_postgresql_version": "unknown",
            "format": "tar.gz",
            "wal_method": "none",
            "wal_source": "archive_command_and_hourly_shipper",
            "observed_wal_start_lsn": _observed_lsn(stderr, "write-ahead log start"),
            "observed_wal_stop_lsn": _observed_lsn(stderr, "write-ahead log stop"),
            "timeline": None,
            "sha256": local_digest,
            "remote_sha256": remote_digest,
            "bytes": size,
            "remote_bytes": remote_size,
            "block_count": len(block_ids),
            "storage_backend": "azure_blob",
            "storage_account": settings.account,
            "container": settings.container,
            "object_key": object_key,
            "manifest_object_key": manifest_key,
            "status": "completed",
        }
        uploader.put_bytes(manifest_key, (json.dumps(manifest, indent=2) + "\n").encode())
        return manifest
    except Exception:
        if process.poll() is None:
            process.kill()
        process.wait()
        raise
    finally:
        if hasattr(uploader, "close") and isinstance(uploader, AzureBlobUploader):
            uploader.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a streamed PostgreSQL physical base backup")
    parser.add_argument("--dsn")
    parser.add_argument("--backup-command", default="pg_basebackup")
    args = parser.parse_args()
    print(json.dumps(backup_postgres_physical(dsn=args.dsn, backup_command=args.backup_command), indent=2))


if __name__ == "__main__":
    main()
