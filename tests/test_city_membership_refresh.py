from shapely.geometry import Polygon

from scripts.geo.city_membership_refresh import build_memberships


def test_intersection_fraction_is_bounded(monkeypatch):
    monkeypatch.setattr("scripts.geo.city_membership_refresh.h3_polygon_mollweide",
                        lambda _: Polygon([(0, 0), (10, 0), (10, 10), (0, 10)]))
    city = {"source_id": "1", "geometry": Polygon([(0, 0), (5, 0), (5, 10), (0, 10)])}
    rows = build_memberships([city], [{"snapshot_id": "s", "h3_cell_id": "h", "h3_resolution": 7}], "DE")
    assert len(rows) == 1
    assert 0 < rows[0]["membership_fraction"] <= 1
    assert rows[0]["city_id"] == "DE:CITY:1"


def test_outside_cell_is_not_assigned(monkeypatch):
    monkeypatch.setattr("scripts.geo.city_membership_refresh.h3_polygon_mollweide",
                        lambda _: Polygon([(0, 0), (1, 0), (1, 1), (0, 1)]))
    city = {"source_id": "1", "geometry": Polygon([(5, 5), (6, 5), (6, 6), (5, 6)])}
    assert build_memberships([city], [{"snapshot_id": "s", "h3_cell_id": "h", "h3_resolution": 7}], "DE") == []


def test_repeat_is_deterministic(monkeypatch):
    polygon = Polygon([(0, 0), (2, 0), (2, 2), (0, 2)])
    monkeypatch.setattr("scripts.geo.city_membership_refresh.h3_polygon_mollweide", lambda _: polygon)
    city = {"source_id": "1", "geometry": polygon}
    cell = {"snapshot_id": "s", "h3_cell_id": "h", "h3_resolution": 7}
    assert build_memberships([city], [cell], "DE") == build_memberships([city], [cell], "DE")
