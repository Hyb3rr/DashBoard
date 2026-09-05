"""Create a native ClickHouse File backup, then upload it to Azure Blob."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import shutil
import tempfile
import uuid
from email.utils import formatdate
from urllib.parse import quote, urlsplit

from app.config.backup import BackupSettings
from scripts.ops.backup_postgres import AzureBlobUploader, _credential


class ClickHouseBackupError(RuntimeError):
    pass


def azure_backup_target(settings: BackupSettings, prefix: str) -> str:
    return f"AzureBlobStorage('{settings.endpoint}', '{settings.container}', '{prefix}')"


def _artifact_path() -> tuple[Path, Path]:
    parent = os.getenv("CLICKHOUSE_BACKUP_TEMP_DIR")
    if parent:
        root = Path(parent)
        root.mkdir(parents=True, exist_ok=True)
        directory = Path(tempfile.mkdtemp(prefix="phase10a3-", dir=root))
    else:
        directory = Path(tempfile.mkdtemp(prefix="phase10a3-"))
    return directory, directory / "clickhouse-native-backup.zip"


def _remove_artifact(directory: Path) -> None:
    shutil.rmtree(directory, ignore_errors=True)


def _verify_remote_blob(settings: BackupSettings, object_key: str) -> tuple[int, str]:
    endpoint = urlsplit(settings.endpoint)
    if endpoint.scheme != "https" or not endpoint.netloc:
        raise ClickHouseBackupError("Azure Blob endpoint must use HTTPS")
    token = _credential(settings).get_token("https://storage.azure.com/.default").token
    path = f"/{settings.container}/{quote(object_key, safe='/')}"
    connection = http.client.HTTPSConnection(endpoint.netloc, timeout=30)
    try:
        connection.request("GET", path, headers={
            "Authorization": f"Bearer {token}",
            "x-ms-version": "2023-11-03",
            "x-ms-date": formatdate(usegmt=True),
        })
        response = connection.getresponse()
        if response.status != 200:
            response.read()
            raise ClickHouseBackupError(f"Azure Blob verification GET failed with HTTP {response.status}")
        content_length = response.getheader("Content-Length")
        if content_length is None:
            raise ClickHouseBackupError("Azure Blob verification response lacks Content-Length")
        try:
            expected_size = int(content_length)
        except ValueError as exc:
            raise ClickHouseBackupError("Azure Blob verification Content-Length is invalid") from exc
        digest = hashlib.sha256()
        size = 0
        while chunk := response.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
        if size != expected_size:
            raise ClickHouseBackupError("Azure Blob verification Content-Length mismatch")
        return size, digest.hexdigest()
    finally:
        connection.close()


def backup_clickhouse(settings: BackupSettings | None = None, database: str | None = None,
                      client=None, uploader=None, artifact_factory=_artifact_path,
                      verifier=None, backup_set_id: str | None = None) -> dict:
    settings = settings or BackupSettings.from_env()
    database = database or os.getenv("CLICKHOUSE_DATABASE", "ipintel")
    owned_client = client is None
    if owned_client:
        from app.db.clickhouse import connect
        client = connect()
    directory, artifact = artifact_factory()
    backup_id = backup_set_id or str(uuid.uuid4())
    stamp = datetime.now(timezone.utc)
    object_key = f"{settings.prefix}/clickhouse/{backup_id}/database.zip"
    try:
        try:
            client.command(f"BACKUP DATABASE `{database}` TO File('{artifact}')")
        except Exception as exc:
            raise ClickHouseBackupError("ClickHouse native BACKUP TO File failed") from exc
        if not artifact.is_file() or artifact.stat().st_size <= 0:
            raise ClickHouseBackupError("ClickHouse native backup artifact is missing or empty")
        digest = hashlib.sha256()
        size = 0
        with artifact.open("rb") as stream:
            payload = stream.read()
            digest.update(payload)
            size = len(payload)
        uploader = uploader or AzureBlobUploader(settings)
        try:
            uploader.put_bytes(object_key, payload, content_type="application/zip")
            remote_size, remote_digest = (verifier or _verify_remote_blob)(settings, object_key)
        except Exception as exc:
            raise ClickHouseBackupError("Azure ClickHouse backup upload or verification failed") from exc
        if remote_size != size:
            raise ClickHouseBackupError("Azure ClickHouse backup size verification failed")
        if remote_digest != digest.hexdigest():
            raise ClickHouseBackupError("Azure ClickHouse backup SHA-256 verification failed")
        manifest = {
            "backup_id": backup_id, "backup_set_id": backup_id, "database": database, "backup_type": "clickhouse_native",
            "created_at": stamp.isoformat(), "completed_at": datetime.now(timezone.utc).isoformat(),
            "storage_backend": "azure_blob", "storage_account": settings.account,
            "container": settings.container, "object_key": object_key,
            "bytes": size, "sha256": digest.hexdigest(), "status": "completed",
        }
        uploader.put_bytes(f"{settings.prefix}/manifests/clickhouse/{backup_id}.json", (json.dumps(manifest, indent=2) + "\n").encode())
        _remove_artifact(directory)
        return manifest
    except Exception:
        raise
    finally:
        if owned_client:
            client.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create a native ClickHouse Azure backup")
    parser.add_argument("--database")
    args = parser.parse_args()
    print(json.dumps(backup_clickhouse(database=args.database), indent=2))
