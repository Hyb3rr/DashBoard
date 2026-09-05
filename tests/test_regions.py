from app.core.regions import market_score


def test_region_score_contract_preserves_trade_freshness_metadata():
    result = market_score({"economic_indicators": {
        "schema_version": 1,
        "market_score": None,
        "market_level": "unknown",
        "trade_data_year": 2022,
        "trade_data_age_years": 3,
        "trade_freshness": "stale",
        "score_status": "insufficient_trade_data",
    }})
    assert result["market_score"] is None
    assert result["trade_data_year"] == 2022
    assert result["trade_freshness"] == "stale"
    assert result["score_status"] == "insufficient_trade_data"


def test_region_score_contract_exposes_market_provenance_and_missing_reason():
    result = market_score({"economic_indicators": {
        "schema_version": 1,
        "market_score": None,
        "score_status": "insufficient_trade_data",
        "missing_reason": "insufficient_trade_data",
        "trade_data_method": None,
        "trade_confidence": None,
    }})
    assert result["market_score"] is None
    assert result["missing_reason"] == "insufficient_trade_data"
    assert result["trade_data_method"] is None
    assert result["trade_confidence"] is None


def test_region_score_contract_preserves_scored_provenance():
    result = market_score({"economic_indicators": {
        "schema_version": 1,
        "market_score": 80.22,
        "market_level": "very_high",
        "score_status": "scored",
        "trade_data_method": "reporter_parent",
        "trade_confidence": "high",
        "trade_data_year": 2025,
    }})
    assert result["market_score"] == 80.22
    assert result["trade_data_method"] == "reporter_parent"
    assert result["trade_confidence"] == "high"
    assert result["trade_data_year"] == 2025
