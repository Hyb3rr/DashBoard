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
