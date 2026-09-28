"""Upload boundary for raw archive storage backends.

The local raw archive depends on this small boundary, not on a cloud SDK.
Azure-specific modules load only when an Azure upload is actually requested.
"""

from __future__ import annotations

import importlib.util
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Protocol

from app.config.backup import BackupSettings


class RawArchiveUploadError(RuntimeError):
    """Signal remote archival or verification failure."""


class RawArchiveUploader(Protocol):
    def put_block(self, key: str, block_id: str, data: bytes) -> None:
        """Upload one staged block to the configured raw archive object."""
        ...

    def put_block_list(self, key: str, block_ids: list[str]) -> None:
        """Commit uploaded blocks in their supplied order as one object."""
        ...

    def put_bytes(self, key: str, data: bytes, content_type: str = "application/json") -> None:
        """Upload a complete byte payload with its declared content type."""
        ...

    def close(self) -> None:
        """Release backend resources held by the uploader."""
        ...


def azure_sdk_available() -> bool:
    """Return whether optional Azure SDK modules are installed."""
    try:
        return all(
            importlib.util.find_spec(module) is not None
            for module in ("azure.core", "azure.identity", "azure.storage.blob")
        )
    except ModuleNotFoundError:
        return False


def block_id(number: int) -> str:
    """Create deterministic block IDs without importing an Azure SDK."""
    return base64.b64encode(f"{number:08d}".encode()).decode()


def create_azure_uploader(settings: BackupSettings) -> tuple[Any, Any]:
    """Load Azure adapter only after backup config and dependency checks pass."""
    from scripts.ops.backup_clickhouse import _verify_remote_blob
    from scripts.ops.backup_postgres import AzureBlobUploader

    return AzureBlobUploader(settings), _verify_remote_blob


def upload_sealed(path: Path, spool_dir: Path, source_id: str,
                  settings: BackupSettings, uploader: RawArchiveUploader, verifier) -> dict:
    """Upload a verified sealed chunk and write its remote manifest."""
    object_key = f"{settings.prefix}/raw-logs/{path.relative_to(spool_dir).as_posix()}"
    archive_source = path.relative_to(spool_dir).parts[0]
    digest = hashlib.sha256()
    size = 0
    block_ids = []
    buffer = bytearray()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
            buffer.extend(chunk)
            while len(buffer) >= settings.part_size:
                current_block_id = block_id(len(block_ids) + 1)
                uploader.put_block(object_key, current_block_id, bytes(buffer[:settings.part_size]))
                del buffer[:settings.part_size]
                block_ids.append(current_block_id)
    if buffer or not block_ids:
        if not buffer:
            raise RawArchiveUploadError("sealed raw archive chunk is empty")
        current_block_id = block_id(len(block_ids) + 1)
        uploader.put_block(object_key, current_block_id, bytes(buffer))
        block_ids.append(current_block_id)
    uploader.put_block_list(object_key, block_ids)
    remote_size, remote_digest = verifier(settings, object_key)
    if (remote_size, remote_digest) != (size, digest.hexdigest()):
        raise RawArchiveUploadError("remote raw archive verification mismatch")
    manifest_key = f"{settings.prefix}/raw-logs/manifests/{archive_source}/{path.stem}.json"
    manifest = {
        "schema_version": 1, "source": archive_source, "chunk_id": path.stem,
        "object_key": object_key, "bytes": size, "sha256": digest.hexdigest(),
        "remote_bytes": remote_size, "remote_sha256": remote_digest,
        "verified_at": datetime.now(timezone.utc).isoformat(), "status": "completed",
    }
    uploader.put_bytes(manifest_key, (json.dumps(manifest, indent=2) + "\n").encode(), content_type="application/json")
    return manifest


def remove_uploaded_artifacts(path: Path) -> None:
    """Remove local artifacts only after successful remote upload."""
    path.unlink()
    path.with_name(path.name + ".json").unlink(missing_ok=True)
