from scripts.ops.country_opportunity_calibration import build_calibration_report


def test_calibration_report_has_distributions_and_flags_low_confidence():
    snapshots = {period: {"countries": [{"country_code": "DE", "qualified_requests": 10, "country_demand_score": 82, "demand_confidence": 0.1}]} for period in ("7d", "30d", "90d")}
    report = build_calibration_report(snapshots, {"DE": {"country_name": "Germany", "market_score": 90}})
    assert report["policy"] == {"market_weight": 0.6, "demand_weight": 0.4, "neutral_demand": 50.0}
    assert report["periods"]["30d"]["distributions"]["opportunity_score"]["count"] == 1
    assert report["periods"]["30d"]["status_counts"] == {"EMERGING": 1}
    assert any(flag["type"] == "high_score_low_confidence" for flag in report["flags"])


def test_calibration_report_does_not_flag_prioritize_with_sufficient_confidence():
    snapshots = {"7d": None, "30d": {"countries": [{"country_code": "DE", "qualified_requests": 10, "country_demand_score": 82, "demand_confidence": 0.8}]}, "90d": None}
    report = build_calibration_report(snapshots, {"DE": {"market_score": 90}})
    assert report["flags"] == []
