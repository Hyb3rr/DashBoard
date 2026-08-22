from __future__ import annotations

import os
from threading import Lock
from pathlib import Path
from contextlib import contextmanager
from typing import Any, Iterator
from ..core import metrics


_pool = None
_pool_dsn: str | None = None
_pool_lock = Lock()


def configured() -> bool:
    return bool(os.getenv("POSTGRES_DSN"))


def connect():
    try:
        import psycopg
    except ImportError as exc:  # pragma: no cover - optional deployment extra
        raise RuntimeError("psycopg is required for DATA_BACKEND=split") from exc
    return psycopg.connect(
        os.environ["POSTGRES_DSN"],
        row_factory=psycopg.rows.dict_row,
    )


def _connection_pool():
    """Return one process-local pool; repositories borrow connections per transaction."""
    global _pool, _pool_dsn
    dsn = os.environ["POSTGRES_DSN"]
    with _pool_lock:
        if _pool is not None and _pool_dsn == dsn:
            return _pool
        if _pool is not None:
            _pool.close()
        try:
            import psycopg
            from psycopg_pool import ConnectionPool
        except ImportError as exc:  # pragma: no cover - optional deployment extra
            raise RuntimeError("psycopg[pool] is required for DATA_BACKEND=split") from exc
        _pool = ConnectionPool(
            conninfo=dsn,
            kwargs={"row_factory": psycopg.rows.dict_row},
            min_size=max(1, int(os.getenv("POSTGRES_POOL_MIN_SIZE", "1"))),
            max_size=max(1, int(os.getenv("POSTGRES_POOL_MAX_SIZE", "10"))),
            open=True,
        )
        _pool_dsn = dsn
        return _pool


def close_pool() -> None:
    global _pool, _pool_dsn
    with _pool_lock:
        if _pool is not None:
            _pool.close()
        _pool = None
        _pool_dsn = None


@contextmanager
def transaction() -> Iterator[Any]:
    with _connection_pool().connection() as conn:
        with conn.transaction():
            yield conn


def health() -> dict[str, Any]:
    finish = metrics.timed("postgres.health_latency_ms")
    try:
        with transaction() as conn:
            conn.execute("SELECT 1")
        metrics.increment("postgres.health_checks")
        return {"status": "ok"}
    except Exception as exc:
        metrics.increment("postgres.health_errors")
        return {"status": "failed", "error": f"{type(exc).__name__}: {exc}"[:240]}
    finally:
        finish()


def ensure_schema() -> None:
    """Apply the idempotent local PostgreSQL schema before split traffic starts."""
    schema_path = Path(__file__).resolve().parents[2] / "infra" / "postgres" / "001_initial.sql"
    sql = schema_path.read_text(encoding="utf-8")
    with transaction() as conn:
        conn.execute(sql)
    
    # Seed region profiles if empty
    from ..config.settings import REGION_SEED_PATH
    if REGION_SEED_PATH.exists():
        import json
        from .repositories import RegionRepository
        try:
            with transaction() as conn:
                existing = conn.execute("SELECT COUNT(*) AS n FROM region_profiles").fetchone()
                if existing and not existing["n"]:
                    payload = json.loads(REGION_SEED_PATH.read_text(encoding="utf-8"))
                    if isinstance(payload, list):
                        RegionRepository().seed(payload)
        except Exception as exc:
            import logging
            logging.getLogger(__name__).warning("Failed to seed region profiles: %s", exc)


def countries_for_ips(ips: list[str]) -> dict[str, dict[str, str | None]]:
    """Resolve a compact ClickHouse IP aggregate through the PG state plane."""
    if not ips:
        return {}
    with transaction() as conn:
        rows = conn.execute(
            """SELECT host(ip) AS ip, country, country_code
               FROM ip_profiles WHERE ip = ANY(%s::inet[])""",
            (ips,),
        ).fetchall()
    return {str(row["ip"]): {"country": row["country"], "country_code": row["country_code"]} for row in rows}
