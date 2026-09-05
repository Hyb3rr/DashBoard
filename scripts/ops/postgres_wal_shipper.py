"""Ship archived PostgreSQL WAL segments to Azure with remote verification."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import time

import psycopg

from app.config.backup import BackupSettings
from scripts.ops.backup_clickhouse import _verify_remote_blob
from scripts.ops.backup_postgres import _PrimaryOnlyRequestsTransport, _credential


WAL_NAME = re.compile(r"^[0-9A-Fa-f]{24}(?:\.history)?$")
DEFAULT_SPOOL_DIR = Path(__file__).resolve().parents[2] / "data" / "postgres-wal-spool"


class AzureWalUploader:
    """Azure Blob file uploader with bounded SDK retries."""

    def __init__(self, settings: BackupSettings):
        from azure.core.pipeline.policies import RetryPolicy
        from azure.storage.blob import BlobServiceClient

        self.settings = settings
        self.service = BlobServiceClient(
            account_url=settings.endpoint,
            credential=_credential(settings),
            retry_policy=RetryPolicy(total_retries=0),
            transport=_PrimaryOnlyRequestsTransport(),
        )
        self.container = self.service.get_container_client(settings.container)

    def upload_file(self, key: str, path: Path) -> str:
        from azure.core.exceptions import ResourceExistsError
        from azure.storage.blob import ContentSettings

        try:
            with path.open("rb") as stream:
                self.container.get_blob_client(key).upload_blob(
                    stream, blob_type="BlockBlob", overwrite=False,
                    content_settings=ContentSettings(content_type="application/octet-stream"),
                )
            return "uploaded"
        except ResourceExistsError:
            return "already_exists"

    def put_manifest(self, key: str, data: bytes) -> str:
        from azure.core.exceptions import ResourceExistsError
        from azure.storage.blob import ContentSettings

        try:
            self.container.get_blob_client(key).upload_blob(
                data, blob_type="BlockBlob", overwrite=False,
                content_settings=ContentSettings(content_type="application/json"),
            )
            return "uploaded"
        except ResourceExistsError:
            return "already_exists"

    def close(self) -> None:
        self.service.close()


def switch_wal(dsn: str) -> str:
    with psycopg.connect(dsn, autocommit=True) as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT pg_switch_wal()")
            return str(cursor.fetchone()[0])


def spool_metrics(spool_dir: str | Path) -> dict:
    spool = Path(spool_dir)
    files = [path for path in spool.iterdir() if path.is_file() and WAL_NAME.fullmatch(path.name)] if spool.exists() else []
    total_bytes = sum(path.stat().st_size for path in files)
    oldest = min((path.stat().st_mtime for path in files), default=None)
    return {
        "pending_wal_count": len(files),
        "pending_wal_bytes": total_bytes,
        "oldest_pending_wal_age_seconds": round(max(0.0, time.time() - oldest), 3) if oldest else 0.0,
    }


def _digest(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return size, digest.hexdigest()


def _wal_manifest(settings: BackupSettings, path: Path, size: int, digest: str,
                  remote_size: int, remote_digest: str) -> tuple[str, bytes]:
    key = f"{settings.prefix}/postgres-pitr/manifests/wal/{path.name}.json"
    manifest = {
        "schema_version": 1,
        "wal_name": path.name,
        "timeline": path.name[:8],
        "wal_kind": "history" if path.name.endswith(".history") else "segment",
        "object_key": f"{settings.prefix}/postgres-pitr/wal/{path.name}",
        "bytes": size,
        "sha256": digest,
        "remote_bytes": remote_size,
        "remote_sha256": remote_digest,
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "status": "completed",
    }
    return key, (json.dumps(manifest, indent=2) + "\n").encode()


def set_low_priority() -> None:
    try:
        os.nice(10)
    except (AttributeError, OSError):
        pass


def ship_wal(settings: BackupSettings | None = None, dsn: str | None = None,
             spool_dir: str | Path | None = None, uploader=None,
             switcher=switch_wal, verifier=None) -> dict:
    """Switch WAL once, ship pending segments, and return backlog metrics."""
    settings = settings or BackupSettings.from_env()
    dsn = dsn or os.getenv("POSTGRES_DSN")
    if not dsn:
        raise RuntimeError("POSTGRES_DSN is required")
    spool = Path(spool_dir or os.getenv("POSTGRES_WAL_SPOOL_DIR", str(DEFAULT_SPOOL_DIR)))
    spool.mkdir(parents=True, exist_ok=True)
    before = spool_metrics(spool)
    trigger_lsn = switcher(dsn)
    paths = sorted((path for path in spool.iterdir() if path.is_file() and WAL_NAME.fullmatch(path.name)), key=lambda path: path.name)
    owned_uploader = uploader is None
    uploader = uploader or AzureWalUploader(settings)
    verified = []
    try:
        for path in paths:
            size, digest = _digest(path)
            object_key = f"{settings.prefix}/postgres-pitr/wal/{path.name}"
            uploader.upload_file(object_key, path)
            remote_size, remote_digest = (verifier or _verify_remote_blob)(settings, object_key)
            if (remote_size, remote_digest) != (size, digest):
                raise RuntimeError(f"remote WAL verification mismatch: {path.name}")
            manifest_key, manifest_body = _wal_manifest(settings, path, size, digest, remote_size, remote_digest)
            uploader.put_manifest(manifest_key, manifest_body)
            path.unlink()
            verified.append(path.name)
    finally:
        if owned_uploader:
            uploader.close()
    return {
        "trigger_lsn": trigger_lsn,
        "verified_wal": verified,
        "before": before,
        "after": spool_metrics(spool),
        "status": "completed",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Ship archived PostgreSQL WAL to Azure")
    parser.add_argument("--dsn")
    parser.add_argument("--spool-dir")
    args = parser.parse_args()
    set_low_priority()
    print(json.dumps(ship_wal(dsn=args.dsn, spool_dir=args.spool_dir), indent=2))


if __name__ == "__main__":
    main()
