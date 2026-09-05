from scripts.geo.overlap_refresh import compute_overlap


def test_directional_overlap_is_not_symmetric():
    rows = [
        {"snapshot_id":"s","country_code":"DE","track":"woodworking","h3_resolution":7,"h3_cell_id":"1","area_id":"A","calibrated_score":1.0},
        {"snapshot_id":"s","country_code":"DE","track":"woodworking","h3_resolution":7,"h3_cell_id":"1","area_id":"B","calibrated_score":1.0},
        {"snapshot_id":"s","country_code":"DE","track":"woodworking","h3_resolution":7,"h3_cell_id":"2","area_id":"B","calibrated_score":1.0},
        {"snapshot_id":"s","country_code":"DE","track":"woodworking","h3_resolution":7,"h3_cell_id":"3","area_id":"B","calibrated_score":1.0},
    ]
    result = compute_overlap(rows)
    assert len(result) == 1
    assert result[0]["overlap_a_to_b"] == 1.0
    assert result[0]["overlap_b_to_a"] == 1 / 3
    assert result[0]["remaining_opportunity_a"] == 0
    assert result[0]["remaining_opportunity_b"] == 2


def test_no_shared_cells_produces_no_pair():
    rows = [{"snapshot_id":"s","country_code":"DE","track":"woodworking","h3_resolution":7,"h3_cell_id":"1","area_id":"A","calibrated_score":1.0},
            {"snapshot_id":"s","country_code":"DE","track":"woodworking","h3_resolution":7,"h3_cell_id":"2","area_id":"B","calibrated_score":1.0}]
    assert compute_overlap(rows) == []
