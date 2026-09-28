"""Shared low-level helpers for market PostgreSQL repositories."""

from __future__ import annotations

from typing import Any


def _executemany(conn: Any, sql: str, values: list[tuple[Any, ...]]) -> None:
    """Execute a batch using psycopg3 while leaving transaction ownership to callers."""
    with conn.cursor() as cursor:
        cursor.executemany(sql, values)
