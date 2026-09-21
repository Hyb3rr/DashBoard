from pathlib import Path


def test_regions_route_reads_city_overall_snapshot_when_published():
    source = Path("app/routers/regions.py").read_text()
    assert "latest_city_overall_snapshot" in source
    assert "city_overall_snapshot" in source
    assert "snapshot_id" in source
    assert "include_overall=False" in source
