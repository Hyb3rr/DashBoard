from scripts.geo import area_membership_refresh as membership
from scripts.geo.area_membership_refresh import _load_boundaries, map_point_to_area


def test_mapping_uses_polygon_and_keeps_outside_unmapped():
    boundaries = [{
        "area_id": "DE:ADM2:0", "admin_level": 2,
        "_feature": {"geometry": {"type": "Polygon", "coordinates": [[[0, 0], [2, 0], [2, 2], [0, 2], [0, 0]]]}}
    }]
    assert map_point_to_area((1, 1), boundaries) == "DE:ADM2:0"
    assert map_point_to_area((3, 3), boundaries) is None


def test_mapping_prefers_deeper_admin_level():
    boundaries = [
        {"area_id": "DE:ADM1:0", "admin_level": 1, "_feature": {"geometry": {"type": "Polygon", "coordinates": [[[0, 0], [4, 0], [4, 4], [0, 4], [0, 0]]]}}},
        {"area_id": "DE:ADM2:0", "admin_level": 2, "_feature": {"geometry": {"type": "Polygon", "coordinates": [[[0, 0], [2, 0], [2, 2], [0, 2], [0, 0]]]}}},
    ]
    assert map_point_to_area((1, 1), boundaries) == "DE:ADM2:0"


def test_boundary_loader_uses_only_persisted_adaptive_levels(tmp_path):
    country_dir = tmp_path / "KOR"
    country_dir.mkdir()
    (country_dir / "ADM1.json").write_text(
        '{"type":"FeatureCollection","features":[]}', encoding="utf-8"
    )
    (country_dir / "ADM2.json").write_text(
        '{"type":"FeatureCollection","features":[]}', encoding="utf-8"
    )
    boundaries, _ = _load_boundaries("KOR", "KR", tmp_path, {1})
    assert boundaries == []


def test_refresh_isolates_country_failures_and_clears_unmapped_membership(monkeypatch):
    class Repository:
        def __init__(self):
            self.states = []
            self.received_updates = []

        def country_iso3(self, country):
            return "AAA" if country == "AA" else None

        def administrative_levels(self, _country):
            return {2}

        def get_job_state(self, _key):
            return None

        def list_local_cells_for_mapping(self, _country):
            return [{"h3_cell_id": "cell-a", "area_id": "stale-area"}]

        def update_local_area_membership(self, updates):
            self.received_updates.extend(updates)
            return 1

        def upsert_job_state(self, state):
            self.states.append(state)

    repo = Repository()
    monkeypatch.setattr(membership, "_load_boundaries", lambda *_args: ([], "source-hash"))
    monkeypatch.setattr(membership, "h3_centroid", lambda _cell: (0.0, 0.0))
    monkeypatch.setattr(membership, "map_point_to_area", lambda _point, _boundaries: None)

    result = membership.refresh_area_membership(repo, countries=["AA", "BB"])

    assert result["status"] == "partial"
    assert result["countries"]["AA"]["status"] == "updated"
    assert result["countries"]["BB"]["status"] == "failed"
    assert repo.received_updates == [{"h3_cell_id": "cell-a", "area_id": None}]
    assert [state["status"] for state in repo.states] == ["processing", "done", "failed"]
