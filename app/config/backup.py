"""Configuration for explicit, off-host backup CLI workloads."""

from __future__ import annotations

from dataclasses import dataclass
import os


@dataclass(frozen=True)
class BackupSettings:
    account: str
    container: str
    auth: str = "service_principal"
    tenant_id: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    prefix: str = "sentinelhub"
    part_size: int = 8 * 1024 * 1024
    endpoint: str | None = None

    def __post_init__(self) -> None:
        if self.part_size <= 0:
            raise ValueError("backup part size must be positive")
        if self.endpoint is None:
            object.__setattr__(self, "endpoint", f"https://{self.account}.blob.core.windows.net")

    @classmethod
    def from_env(cls) -> "BackupSettings":
        names = ("BACKUP_AZURE_ACCOUNT", "BACKUP_AZURE_CONTAINER")
        values = {name: os.getenv(name, "").strip() for name in names}
        missing = [name for name, value in values.items() if not value]
        if missing:
            raise RuntimeError("missing backup configuration: " + ", ".join(missing))
        backend = os.getenv("BACKUP_STORAGE_BACKEND", "azure_blob").strip().lower()
        if backend != "azure_blob":
            raise RuntimeError("unsupported backup storage backend: " + backend)
        auth = os.getenv("BACKUP_AZURE_AUTH", "service_principal").strip().lower()
        if auth not in {"service_principal", "managed_identity"}:
            raise RuntimeError("unsupported Azure backup authentication: " + auth)
        credentials = {name: os.getenv(name, "").strip() for name in ("AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET")}
        if auth == "service_principal" and any(not value for value in credentials.values()):
            missing_credentials = [name for name, value in credentials.items() if not value]
            raise RuntimeError("missing service principal configuration: " + ", ".join(missing_credentials))
        try:
            part_size = int(os.getenv("BACKUP_AZURE_PART_SIZE_BYTES", str(8 * 1024 * 1024)))
        except ValueError as exc:
            raise RuntimeError("BACKUP_AZURE_PART_SIZE_BYTES must be an integer") from exc
        return cls(values[names[0]], values[names[1]], auth, credentials["AZURE_TENANT_ID"] or None, credentials["AZURE_CLIENT_ID"] or None, credentials["AZURE_CLIENT_SECRET"] or None, os.getenv("BACKUP_AZURE_PREFIX", "sentinelhub").strip("/") or "sentinelhub", part_size)
