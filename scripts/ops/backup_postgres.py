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
    """Create the configured Azure identity credential."""
    from azure.identity import ClientSecretCredential, ManagedIdentityCredential

    if settings.auth == "service_principal":
        return ClientSecretCredential(settings.tenant_id, settings.client_id, settings.client_secret)
    if settings.auth == "managed_identity":
        return ManagedIdentityCredential()
    raise RuntimeError("unsupported Azure backup authentication: " + settings.auth)


class AzureBlobUploader:
    """Azure Block Blob transport with bounded, explicit SDK retry policy."""

    def __init__(self, settings: BackupSettings, blob_service=None, credential=None):
        """Create a Blob transport with SDK retries disabled for explicit control."""
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
        """Return a blob client for one object key."""
        return self.container.get_blob_client(key)

    def put_block(self, key: str, block_id: str, data: bytes) -> None:
        """Stage one non-empty block for a block blob."""
        if not data:
            raise ValueError("Azure block payload must not be empty")
        self._blob(key).stage_block(block_id=block_id, data=data)

    def put_block_list(self, key: str, block_ids: list[str]) -> None:
        """Commit a non-empty ordered block list as the completed blob."""
        if not block_ids:
            raise ValueError("Azure block list must not be empty")
        self._blob(key).commit_block_list(block_ids)

    def put_bytes(self, key: str, data: bytes, content_type: str = "application/json") -> None:
        """Upload one small object without overwriting an existing key."""
        from azure.storage.blob import ContentSettings

        self._blob(key).upload_blob(data, blob_type="BlockBlob", overwrite=False, content_settings=ContentSettings(content_type=content_type))

    def get_bytes(self, key: str) -> bytes | None:
        """Read a small blob, returning None only when Azure reports it missing."""
        from azure.core.exceptions import ResourceNotFoundError

        try:
            return self._blob(key).download_blob().readall()
        except ResourceNotFoundError:
            return None

    def exists(self, key: str) -> bool:
        """Check blob existence without hiding authentication or transport errors."""
        from azure.core.exceptions import ResourceNotFoundError

        try:
            self._blob(key).get_blob_properties()
            return True
        except ResourceNotFoundError:
            return False

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
            """Discard unsupported host hints before sending to the primary endpoint."""
            kwargs.pop("hosts", None)
            kwargs.pop("location_mode", None)
            return super().send(request, **kwargs)

    return PrimaryOnlyRequestsTransport()


def _block_id(number: int) -> str:
    """Encode a stable, fixed-width Azure block identifier."""
    return base64.b64encode(f"{number:08d}".encode()).decode()


def _read_stderr(stream, result: list[str]) -> None:
    """Drain pg_dump stderr in a background thread to prevent pipe blockage."""
    result.append(stream.read().decode("utf-8", "replace"))


def _dump_tool_version(dump_command: str) -> str:
    """Return the pg_dump version string or an explicit unknown marker."""
    try:
        result = subprocess.run([dump_command, "--version"], capture_output=True, text=True, check=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    return (result.stdout or result.stderr).strip() or "unknown"


def _stream_dump_blocks(process, uploader, key: str, part_size: int) -> tuple[str, int, list[str], bytearray]:
    """Stream complete pg_dump blocks and retain the final partial block."""
    assert process.stdout
    digest, size, block_ids, buffer = hashlib.sha256(), 0, [], bytearray()
    while chunk := process.stdout.read(1024 * 1024):
        digest.update(chunk)
        size += len(chunk)
        buffer.extend(chunk)
        while len(buffer) >= part_size:
            block_id = _block_id(len(block_ids) + 1)
            uploader.put_block(key, block_id, bytes(buffer[:part_size]))
            del buffer[:part_size]
            block_ids.append(block_id)
    return digest.hexdigest(), size, block_ids, buffer


def backup_postgres(settings: BackupSettings | None = None, dsn: str | None = None,
                   dump_command: str = "pg_dump", uploader=None,
                   backup_set_id: str | None = None) -> dict:
    """Stream a custom-format database dump and publish its verified manifest."""
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
    try:
        checksum, size, block_ids, buffer = _stream_dump_blocks(process, uploader, key, settings.part_size)
        code = process.wait(); stderr_thread.join(timeout=5)
        if code:
            raise RuntimeError(f"pg_dump failed with exit {code}: {stderr_result[0][-500:]}")
        if buffer or not block_ids:
            final_payload = bytes(buffer)
            if not final_payload:
                raise RuntimeError("final PostgreSQL backup block is empty")
            block_id = _block_id(len(block_ids) + 1)
            uploader.put_block(key, block_id, final_payload)
            block_ids.append(block_id)
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
        "source_postgresql_version": source_version, "format": "custom", "sha256": checksum,
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
