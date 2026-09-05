from scripts.geo.local_calibration import _select, _stability, _transform


def test_calibration_transforms_are_bounded_and_monotonic():
    values = [10.0, 20.0, 30.0, 40.0]
    for method in ("percentile", "robust_z"):
        result = _transform(values, method)
        assert result == sorted(result)
        assert all(0.0 <= value <= 1.0 for value in result)


def test_stability_is_deterministic():
    values = [float(value) for value in range(10, 110)]
    assert _stability(values, "percentile") == _stability(values, "percentile")


def test_selection_prefers_rank_stability_then_distortion():
    metrics = {
        "percentile": {"spearman_rank_correlation": .99, "p95_score_shift": .2, "median_absolute_score_shift": .1},
        "robust_z": {"spearman_rank_correlation": .98, "p95_score_shift": .01, "median_absolute_score_shift": .01},
    }
    assert _select(metrics) == "percentile"
