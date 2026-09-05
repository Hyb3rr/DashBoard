"""Create one verified PostgreSQL + ClickHouse backup set."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
import uuid

from app.config.backup import BackupSettings
from scripts.ops.backup_clickhouse import backup_clickhouse
from scripts.ops.backup_postgres import AzureBlobUploader, backup_postgres


def _component(manifest: dict, component_name: str, settings: BackupSettings) -> dict:
    return {
        "backup_id": manifest["backup_id"],
        "object_key": manifest["object_key"],
        "manifest_object_key": f"{settings.prefix}/manifests/{component_name}/{manifest['backup_id']}.json",
        "bytes": manifest["bytes"],
        "sha256": manifest["sha256"],
        "status": manifest["status"],
    }


def backup_set(settings: BackupSettings | None = None, dsn: str | None = None,
               database: str | None = None, backup_set_id: str | None = None,
               postgres_backup=backup_postgres,
               clickhouse_backup=backup_clickhouse,
               uploader_factory=AzureBlobUploader) -> dict:
    """Create both components and publish a COMPLETED set manifest last."""
    settings = settings or BackupSettings.from_env()
    dsn = dsn or os.getenv("POSTGRES_DSN")
    if not dsn:
        raise RuntimeError("POSTGRES_DSN is required")
    database = database or os.getenv("CLICKHOUSE_DATABASE", "ipintel")
    backup_set_id = backup_set_id or str(uuid.uuid4())
    started_at = datetime.now(timezone.utc)

    postgres = postgres_backup(settings=settings, dsn=dsn, backup_set_id=backup_set_id)
    clickhouse = clickhouse_backup(settings=settings, database=database, backup_set_id=backup_set_id)
    components = {
        "postgres": _component(postgres, "postgres", settings),
        "clickhouse": _component(clickhouse, "clickhouse", settings),
    }
    if any(component["status"] != "completed" for component in components.values()):
        raise RuntimeError("backup set components must be completed before set manifest")

    manifest = {
        "schema_version": 1,
        "backup_set_id": backup_set_id,
        "started_at": started_at.isoformat(),
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "status": "completed",
        "storage_backend": "azure_blob",
        "storage_account": settings.account,
        "container": settings.container,
        **components,
    }
    uploader = uploader_factory(settings)
    key = f"{settings.prefix}/manifests/sets/{backup_set_id}.json"
    uploader.put_bytes(key, (json.dumps(manifest, indent=2) + "\n").encode())
    manifest["object_key"] = key
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create a verified PostgreSQL and ClickHouse backup set")
    parser.add_argument("--database")
    args = parser.parse_args()
    print(json.dumps(backup_set(database=args.database), indent=2))
