"""Upload boundary for raw archive storage backends.

The local raw archive depends on this small boundary, not on a cloud SDK.
Azure-specific modules load only when an Azure upload is actually requested.
"""

from __future__ import annotations

import importlib.util
import base64
from typing import Any, Protocol

from app.config.backup import BackupSettings


class RawArchiveUploader(Protocol):
    def put_block(self, key: str, block_id: str, data: bytes) -> None: ...

    def put_block_list(self, key: str, block_ids: list[str]) -> None: ...

    def put_bytes(self, key: str, data: bytes, content_type: str = "application/json") -> None: ...

    def close(self) -> None: ...


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
