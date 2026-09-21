import json
from pathlib import Path

import pytest

from app.core.country_demand import build_country_opportunities


CASES = json.loads(Path("tests/fixtures/country_opportunity_eval.json").read_text())


@pytest.mark.parametrize("case", CASES, ids=[case["name"] for case in CASES])
def test_country_opportunity_eval_case(case):
    demand = {"country_code": "XX", "qualified_requests": 10, "country_demand_score": case["demand"], "demand_confidence": case["confidence"]}
    row = build_country_opportunities({"30d": {"countries": [demand]}}, {"XX": {"country_name": "Evalland", "market_score": case["market"]}})["countries"][0]
    assert row["opportunity_status"] == case["expected_status"]
    if case["demand"] is None:
        assert row["opportunity_score"] is None
    else:
        assert row["adjusted_demand_score"] == round(50 + case["confidence"] * (case["demand"] - 50), 1)
        assert "Market Score" in row["opportunity_reason"]
        assert "Demand Confidence" in row["opportunity_reason"]


def test_low_confidence_never_prioritizes_even_when_score_is_high():
    row = build_country_opportunities({"30d": {"countries": [{"country_code": "XX", "qualified_requests": 10, "country_demand_score": 100, "demand_confidence": 0.01}]}}, {"XX": {"market_score": 100}})["countries"][0]
    assert row["opportunity_score"] >= 70
    assert row["opportunity_status"] != "PRIORITIZE"
