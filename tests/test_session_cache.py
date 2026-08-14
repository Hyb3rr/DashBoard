from fastapi.testclient import TestClient

from app.main import app
from app.core import db


def test_shared_cache_helper_is_served():
    response = TestClient(app).get("/static/hub-cache.js")
    assert response.status_code == 200
    assert "cachedFetch" in response.text
    assert "invalidateHubCache" in response.text


def test_country_code_index_exists(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "hub.db")
    monkeypatch.setattr(db, "REGION_SEED_PATH", tmp_path / "missing-seed.json")
    db._seed_cache.clear()
    conn = db.connect()
    try:
        indexes = {row["name"] for row in conn.execute("PRAGMA index_list(ip_profiles)")}
        assert "idx_ip_profiles_country_code" in indexes
    finally:
        conn.close()
