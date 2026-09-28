"""Apply ordered ClickHouse migrations before runtime schema verification."""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
MIGRATION_DIR = PROJECT_ROOT / "infra" / "clickhouse"
_MIGRATION_RE = re.compile(r"^(?P<version>\d+)_(?P<name>.+)\.sql$")

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def statements(sql: str) -> list[str]:
    """Split a migration script into non-empty semicolon-delimited commands."""
    return [statement.strip() for statement in sql.split(";") if statement.strip()]


def _driver_text(value: Any) -> str:
    """Normalize ClickHouse driver string values, including fixed-string bytes."""
    return value.decode("utf-8") if isinstance(value, bytes) else str(value)


def discover(directory: Path = MIGRATION_DIR) -> list[tuple[int, str, str, str]]:
    """Load migrations in numeric order and reject version gaps."""
    migrations = []
    for path in sorted(directory.glob("*.sql")):
        match = _MIGRATION_RE.match(path.name)
        if not match:
            continue
        sql = path.read_text(encoding="utf-8")
        migrations.append((
            int(match.group("version")),
            path.name,
            hashlib.sha256(sql.encode("utf-8")).hexdigest(),
            sql,
        ))
    versions = [migration[0] for migration in migrations]
    if versions != list(range(1, len(versions) + 1)):
        raise RuntimeError(f"ClickHouse migrations are not contiguous: {versions}")
    return migrations


def _ensure_migration_ledger(client: Any, database: str) -> None:
    """Create the ClickHouse table that records applied migration checksums."""
    client.command(f"""
        CREATE TABLE IF NOT EXISTS {database}.schema_migrations (
            version UInt32,
            filename String,
            checksum_sha256 FixedString(64),
            applied_at DateTime64(3, 'UTC') DEFAULT now64(3)
        ) ENGINE = MergeTree ORDER BY version
    """)


def _applied_migrations(client: Any, database: str) -> dict[int, tuple[str, str]]:
    """Read applied migration filenames and checksums keyed by version."""
    rows = client.query(
        f"SELECT version, filename, checksum_sha256 FROM {database}.schema_migrations ORDER BY version"
    ).result_rows
    return {
        int(row[0]): (_driver_text(row[1]), _driver_text(row[2]))
        for row in rows
    }


def _apply_migration(client: Any, database: str,
                     migration: tuple[int, str, str, str]) -> None:
    """Execute one migration and record its immutable checksum."""
    version, filename, checksum, sql = migration
    for statement in statements(sql):
        client.command(statement)
    client.insert(
        f"{database}.schema_migrations",
        [[version, filename, checksum]],
        column_names=["version", "filename", "checksum_sha256"],
    )


def apply(client: Any, database: str = "ipintel", directory: Path = MIGRATION_DIR) -> None:
    """Apply only unapplied migrations and reject changes to recorded files."""
    _ensure_migration_ledger(client, database)
    applied = _applied_migrations(client, database)
    for migration in discover(directory):
        version, filename, checksum, _sql = migration
        existing = applied.get(version)
        if existing:
            if existing != (filename, checksum):
                raise RuntimeError(f"ClickHouse migration checksum mismatch for {filename}")
            continue
        _apply_migration(client, database, migration)
        applied[version] = (filename, checksum)


def apply_configured() -> None:
    """Bootstrap the target database and apply its configured migrations."""
    from app.db.clickhouse import connect
    import os

    database = os.getenv("CLICKHOUSE_DATABASE", "ipintel")
    bootstrap = connect(database="default")
    try:
        bootstrap.command(f"CREATE DATABASE IF NOT EXISTS {database}")
    finally:
        bootstrap.close()
    client = connect(database=database)
    try:
        apply(client, database)
    finally:
        client.close()


if __name__ == "__main__":
    apply_configured()
