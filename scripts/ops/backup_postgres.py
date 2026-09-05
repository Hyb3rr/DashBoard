"""Stream a PostgreSQL custom dump to Azure Blob with the official SDK."""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
import subprocess
import threading
import uuid

from app.config.backup import BackupSettings


def _credential(settings: BackupSettings):
    from azure.identity import ClientSecretCredential, ManagedIdentityCredential

    if settings.auth == "service_principal":
        return ClientSecretCredential(settings.tenant_id, settings.client_id, settings.client_secret)
    if settings.auth == "managed_identity":
        return ManagedIdentityCredential()
    raise RuntimeError("unsupported Azure backup authentication: " + settings.auth)


class AzureBlobUploader:
    """Azure Block Blob transport with bounded, explicit SDK retry policy."""

    def __init__(self, settings: BackupSettings, blob_service=None, credential=None):
        from azure.core.pipeline.policies import RetryPolicy
        from azure.storage.blob import BlobServiceClient

        self.settings = settings
        self.service = blob_service or BlobServiceClient(
            account_url=settings.endpoint,
            credential=credential or _credential(settings),
            retry_policy=RetryPolicy(total_retries=0),
            transport=_PrimaryOnlyRequestsTransport(),
        )
        self.container = self.service.get_container_client(settings.container)
        self._closed = False

    def _blob(self, key: str):
        return self.container.get_blob_client(key)

    def put_block(self, key: str, block_id: str, data: bytes) -> None:
        if not data:
            raise ValueError("Azure block payload must not be empty")
        self._blob(key).stage_block(block_id=block_id, data=data)

    def put_block_list(self, key: str, block_ids: list[str]) -> None:
        if not block_ids:
            raise ValueError("Azure block list must not be empty")
        self._blob(key).commit_block_list(block_ids)

    def put_bytes(self, key: str, data: bytes, content_type: str = "application/json") -> None:
        from azure.storage.blob import ContentSettings

        self._blob(key).upload_blob(data, blob_type="BlockBlob", overwrite=False, content_settings=ContentSettings(content_type=content_type))

    def close(self) -> None:
        """Release SDK transport resources; safe to call more than once."""
        if not self._closed:
            close = getattr(self.service, "close", None)
            if close:
                close()
            self._closed = True


def _PrimaryOnlyRequestsTransport():
    """Build the SDK transport only when an Azure client is actually needed."""
    from azure.core.pipeline.transport import RequestsTransport

    class PrimaryOnlyRequestsTransport(RequestsTransport):
        """Use the primary Blob endpoint and discard unsupported host metadata."""

        def send(self, request, **kwargs):
            kwargs.pop("hosts", None)
            kwargs.pop("location_mode", None)
            return super().send(request, **kwargs)

    return PrimaryOnlyRequestsTransport()


def _block_id(number: int) -> str:
    return base64.b64encode(f"{number:08d}".encode()).decode()


def _read_stderr(stream, result: list[str]) -> None:
    result.append(stream.read().decode("utf-8", "replace"))


def _dump_tool_version(dump_command: str) -> str:
    try:
        result = subprocess.run([dump_command, "--version"], capture_output=True, text=True, check=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    return (result.stdout or result.stderr).strip() or "unknown"


def backup_postgres(settings: BackupSettings | None = None, dsn: str | None = None,
                   dump_command: str = "pg_dump", uploader=None,
                   backup_set_id: str | None = None) -> dict:
    settings = settings or BackupSettings.from_env()
    dsn = dsn or os.getenv("POSTGRES_DSN")
    if not dsn:
        raise RuntimeError("POSTGRES_DSN is required")
    uploader = uploader or AzureBlobUploader(settings)
    backup_id = backup_set_id or str(uuid.uuid4())
    created_at = datetime.now(timezone.utc)
    key = f"{settings.prefix}/postgres/{backup_id}/database.dump"
    source_version = _dump_tool_version(dump_command)
    process = subprocess.Popen([dump_command, "--format=custom", "--dbname", dsn], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stderr_result: list[str] = []
    stderr_thread = threading.Thread(target=_read_stderr, args=(process.stderr, stderr_result), daemon=True)
    stderr_thread.start()
    digest, size, block_ids, buffer = hashlib.sha256(), 0, [], bytearray()
    try:
        assert process.stdout
        while chunk := process.stdout.read(1024 * 1024):
            digest.update(chunk); size += len(chunk); buffer.extend(chunk)
            while len(buffer) >= settings.part_size:
                block_id = _block_id(len(block_ids) + 1)
                uploader.put_block(key, block_id, bytes(buffer[:settings.part_size]))
                del buffer[:settings.part_size]; block_ids.append(block_id)
        code = process.wait(); stderr_thread.join(timeout=5)
        if code:
            raise RuntimeError(f"pg_dump failed with exit {code}: {stderr_result[0][-500:]}")
        if buffer or not block_ids:
            block_id = _block_id(len(block_ids) + 1)
            final_payload = bytes(buffer)
            if not final_payload:
                raise RuntimeError("final PostgreSQL backup block is empty")
            uploader.put_block(key, block_id, final_payload); block_ids.append(block_id)
        uploader.put_block_list(key, block_ids)
    except Exception:
        if process.poll() is None:
            process.kill()
        process.wait()
        raise
    completed_at = datetime.now(timezone.utc)
    manifest = {
        "backup_id": backup_id, "backup_set_id": backup_id, "database": "postgresql", "backup_type": "logical",
        "created_at": created_at.isoformat(), "completed_at": completed_at.isoformat(),
        "source_postgresql_version": source_version, "format": "custom", "sha256": digest.hexdigest(),
        "bytes": size, "block_count": len(block_ids), "storage_backend": "azure_blob",
        "storage_account": settings.account, "container": settings.container,
        "object_key": key, "status": "completed",
    }
    uploader.put_bytes(f"{settings.prefix}/manifests/postgres/{backup_id}.json", (json.dumps(manifest, indent=2) + "\n").encode())
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create a PostgreSQL backup in Azure Blob")
    parser.add_argument("--dump-command", default="pg_dump")
    args = parser.parse_args()
    print(json.dumps(backup_postgres(dump_command=args.dump_command), indent=2))
