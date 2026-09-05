"""Ordered PostgreSQL migration tracking and existing-schema adoption."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


MIGRATION_DIR = Path(__file__).resolve().parents[2] / "infra" / "postgres"
_MIGRATION_RE = re.compile(r"^(?P<version>\d+)_(?P<name>.+)\.sql$")
_TABLE_RE = re.compile(r"CREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\s+([\w\".]+)", re.IGNORECASE)


@dataclass(frozen=True)
class Migration:
    version: int
    filename: str
    sql: str
    checksum_sha256: str
    tables: frozenset[str]


def discover(directory: Path = MIGRATION_DIR) -> list[Migration]:
    migrations: list[Migration] = []
    for path in sorted(directory.glob("*.sql")):
        match = _MIGRATION_RE.match(path.name)
        if not match:
            continue
        sql = path.read_text(encoding="utf-8")
        tables = frozenset(
            name.strip('"').split(".")[-1].lower()
            for name in _TABLE_RE.findall(sql)
        )
        migrations.append(
            Migration(
                version=int(match.group("version")),
                filename=path.name,
                sql=sql,
                checksum_sha256=hashlib.sha256(sql.encode("utf-8")).hexdigest(),
                tables=tables,
            )
        )
    versions = [migration.version for migration in migrations]
    if versions != list(range(versions[0], versions[-1] + 1)):
        raise RuntimeError(f"PostgreSQL migrations are not contiguous: {versions}")
    return migrations


def _table_exists(conn: Any, table_name: str) -> bool:
    row = conn.execute("SELECT to_regclass(%s) AS relation", (f"public.{table_name}",)).fetchone()
    return bool(row and row["relation"])


def _record(conn: Any, migration: Migration) -> None:
    conn.execute(
        """INSERT INTO schema_migrations
           (version, filename, checksum_sha256, status)
           VALUES (%s, %s, %s, 'applied')""",
        (migration.version, migration.filename, migration.checksum_sha256),
    )


def _record_if_missing(conn: Any, migration: Migration, applied: dict[int, Any]) -> None:
    if migration.version not in applied:
        _record(conn, migration)
        applied[migration.version] = {
            "filename": migration.filename,
            "checksum_sha256": migration.checksum_sha256,
            "status": "applied",
        }


def _validate_applied(conn: Any, migration: Migration, row: Any) -> None:
    if row["filename"] != migration.filename or row["checksum_sha256"] != migration.checksum_sha256:
        raise RuntimeError(
            f"Migration checksum mismatch for {migration.filename}: "
            f"database has {row['filename']} / {row['checksum_sha256']}"
        )
    if row["status"] != "applied":
        raise RuntimeError(f"Migration {migration.filename} is not applied: {row['status']}")


def apply_after_base_schema(conn: Any, migrations: list[Migration] | None = None) -> None:
    """Track 000 and adopt/apply migrations after 001_initial.sql.

    ``postgres.ensure_schema`` has already applied 001 in the explicit
    bootstrap path. Existing databases are adopted only when every table from
    002 onward exists. A partially migrated database fails closed.
    """
    migrations = migrations or discover()
    ledger = migrations[0]
    base = migrations[1]
    missing_base = sorted(table for table in base.tables if not _table_exists(conn, table))
    if missing_base:
        raise RuntimeError(f"Base schema is incomplete; missing tables: {', '.join(missing_base)}")
    conn.execute(ledger.sql)
    rows = conn.execute(
        "SELECT version, filename, checksum_sha256, status FROM schema_migrations ORDER BY version"
    ).fetchall()
    applied = {int(row["version"]): row for row in rows}

    for migration in migrations:
        if migration.version in applied:
            _validate_applied(conn, migration, applied[migration.version])

    if 1 not in applied:
        later_tables = set().union(*(migration.tables for migration in migrations[2:]))
        present = {table for table in later_tables if _table_exists(conn, table)}
        if present and present != later_tables:
            missing = ", ".join(sorted(later_tables - present))
            raise RuntimeError(f"Cannot adopt partially migrated database; missing tables: {missing}")
        if present == later_tables:
            _record_if_missing(conn, ledger, applied)
            _record_if_missing(conn, base, applied)
            for migration in migrations[2:]:
                _record_if_missing(conn, migration, applied)
            return
        _record_if_missing(conn, ledger, applied)
        _record_if_missing(conn, base, applied)

    for migration in migrations[2:]:
        if migration.version in applied:
            continue
        conn.execute(migration.sql)
        _record(conn, migration)
