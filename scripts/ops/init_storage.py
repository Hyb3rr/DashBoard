"""Explicit PostgreSQL and ClickHouse schema bootstrap."""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

def main() -> None:
    from app.core.market_catalog import catalog_rows
    from app.db import clickhouse
    from app.db import migrations
    from app.db import postgres
    from app.db.market_repository import MarketRepository

    try:
        with postgres.transaction() as conn:
            base_exists = bool(
                conn.execute(
                    "SELECT to_regclass('public.ip_minute_features') AS relation"
                ).fetchone()["relation"]
            )
        if not base_exists:
            postgres.ensure_schema()
        with postgres.transaction() as conn:
            migrations.apply_after_base_schema(conn)
        MarketRepository().upsert_catalog(catalog_rows())
        clickhouse.ensure_schema()
        print("Storage schema and market catalog ready")
    finally:
        postgres.close_pool()


if __name__ == "__main__":
    main()
