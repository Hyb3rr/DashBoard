from fastapi.testclient import TestClient
import pytest

from app.main import app


def test_shared_cache_helper_is_served():
    response = TestClient(app).get("/static/hub-cache.js")
    assert response.status_code == 200
    assert "cachedFetch" in response.text
    assert "invalidateHubCache" in response.text


@pytest.mark.integration
def test_country_code_index_exists():
    pytest.skip("Requires PostgreSQL schema verification")
