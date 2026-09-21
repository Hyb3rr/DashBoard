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
    return [statement.strip() for statement in sql.split(";") if statement.strip()]


def _driver_text(value: Any) -> str:
    return value.decode("utf-8") if isinstance(value, bytes) else str(value)


def discover(directory: Path = MIGRATION_DIR) -> list[tuple[int, str, str, str]]:
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


def apply(client: Any, database: str = "ipintel", directory: Path = MIGRATION_DIR) -> None:
    client.command(f"""
        CREATE TABLE IF NOT EXISTS {database}.schema_migrations (
            version UInt32,
            filename String,
            checksum_sha256 FixedString(64),
            applied_at DateTime64(3, 'UTC') DEFAULT now64(3)
        ) ENGINE = MergeTree ORDER BY version
    """)
    rows = client.query(
        f"SELECT version, filename, checksum_sha256 FROM {database}.schema_migrations ORDER BY version"
    ).result_rows
    applied = {
        int(row[0]): (_driver_text(row[1]), _driver_text(row[2]))
        for row in rows
    }
    for version, filename, checksum, sql in discover(directory):
        existing = applied.get(version)
        if existing:
            if existing != (filename, checksum):
                raise RuntimeError(f"ClickHouse migration checksum mismatch for {filename}")
            continue
        for statement in statements(sql):
            client.command(statement)
        client.insert(
            f"{database}.schema_migrations",
            [[version, filename, checksum]],
            column_names=["version", "filename", "checksum_sha256"],
        )
        applied[version] = (filename, checksum)


def apply_configured() -> None:
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
