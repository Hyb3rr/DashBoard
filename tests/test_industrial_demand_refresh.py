from datetime import datetime, timezone

from app.services import industrial_demand


def _matrix():
    return {"schema_version": "market-demand-v2", "products": [
        {"product_id": "panel_saw", "display_name": "Panel Saw", "category": "woodworking",
         "processes": ["panel_cutting"], "industries": ["furniture"], "hs_codes": ["846591"],
         "mapping_type": "direct", "rationale": "direct", "source_refs": ["test"], "status": "ok"},
    ] * 14, "industry_proxy": {"product_id": "proxy", "role": "evidence_only"}, "scoring": "evidence_only"}


def test_build_rows_keeps_category_proxy_explicit(monkeypatch):
    monkeypatch.setattr(industrial_demand, "load_matrix", lambda _: _matrix())
    rows = industrial_demand.build_evidence_rows(_matrix(), [{
        "geo_unit_id": "VN:ADM1:BD", "country_code": "VN", "track": "woodworking",
        "observed_value": 0, "source_snapshot_id": "osm-1",
    }], "snap-1", "2026-09-09T00:00:00+00:00")
    assert rows[0]["observed_value"] == 0
    assert rows[0]["unit"] == "weighted_mapped_establishments"
    assert any("category-level proxy" in item for item in rows[0]["limitations"])
    assert any("same source track" in item for item in rows[0]["limitations"])
    assert rows[0]["source_geo_scope"] == "geo_unit"


def test_refresh_publishes_only_after_batch_write(monkeypatch):
    class Repo:
        def __init__(self): self.calls = []
        def list_industrial_demand_inputs(self, country): return []
        def create_industrial_demand_snapshot(self, item): self.calls.append("create")
        def upsert_industrial_demand_evidence(self, rows): self.calls.append("write")
        def publish_industrial_demand_snapshot(self, snapshot, count): self.calls.append("publish"); return True
    repo = Repo()
    monkeypatch.setattr(industrial_demand, "load_matrix", lambda _: _matrix())
    result = industrial_demand.refresh(repo, now=datetime(2026, 9, 9, tzinfo=timezone.utc))
    assert result["status"] == "published"
    assert repo.calls == ["create", "write", "publish"]


def test_refresh_leaves_snapshot_unpublished_when_write_fails(monkeypatch):
    class Repo:
        def list_industrial_demand_inputs(self, country): return []
        def create_industrial_demand_snapshot(self, item): pass
        def upsert_industrial_demand_evidence(self, rows): raise RuntimeError("write failed")
        def publish_industrial_demand_snapshot(self, snapshot, count): raise AssertionError("must not publish")
    monkeypatch.setattr(industrial_demand, "load_matrix", lambda _: _matrix())
    try:
        industrial_demand.refresh(Repo(), now=datetime(2026, 9, 9, tzinfo=timezone.utc))
    except RuntimeError as exc:
        assert str(exc) == "write failed"
    else:
        raise AssertionError("refresh should fail")
