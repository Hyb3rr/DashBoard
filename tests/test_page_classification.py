from app.core.page_classification import classify_page, is_product_page


def test_product_rule_ignores_query_string():
    rules = [{"pattern": "/products/%", "page_type": "product", "priority": 1}]
    assert classify_page("/products/laser?utm_source=ad", rules) == "product"
    assert is_product_page("/about", rules) is False


def test_priority_wins_and_inactive_rules_do_not_match():
    rules = [
        {"id": 1, "pattern": "/catalog/%", "page_type": "content", "priority": 1},
        {"id": 2, "pattern": "/catalog/%", "page_type": "product", "priority": 2},
        {"id": 3, "pattern": "/catalog/%", "page_type": "other", "priority": 99, "active": False},
    ]
    assert classify_page("/catalog/cnc", rules) == "product"


def test_unknown_path_is_other_and_never_product():
    assert classify_page("/random", []) == "other"
    assert not is_product_page(None, [])
