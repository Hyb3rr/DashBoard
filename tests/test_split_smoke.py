"""Minimal native HTTP smoke test for the live split backend."""

import os

import pytest


@pytest.mark.integration
@pytest.mark.smoke
def test_split_live_http_smoke():
    if os.getenv("DATA_BACKEND", "").strip().lower() != "split":
        pytest.skip("DATA_BACKEND=split is required")
    if not os.getenv("POSTGRES_DSN") or not os.getenv("CLICKHOUSE_HOST"):
        pytest.skip("native PostgreSQL and ClickHouse are required")

    from fastapi.testclient import TestClient
    from app.main import app

    with TestClient(app) as client:
        checks = (
            ("/health", 200),
            ("/api/analytics/traffic?range=1h&mode=live", 200),
            ("/api/ips/summary?mode=live", 200),
            ("/api/ips/page?page=1&page_size=50&mode=live", 200),
            ("/api/ips/snapshot?limit=50&mode=live", 200),
        )
        for path, expected in checks:
            response = client.get(path)
            assert response.status_code == expected, (path, response.text[:500])
