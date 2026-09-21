from app.db import market_repository


def test_city_overall_repository_exposes_publish_and_latest_contract():
    source = market_repository.MarketRepository
    assert hasattr(source, "create_city_overall_snapshot")
    assert hasattr(source, "write_city_overall_rows")
    assert hasattr(source, "publish_city_overall_snapshot")
    assert hasattr(source, "latest_city_overall_snapshot")
