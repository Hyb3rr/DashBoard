from pathlib import Path


def test_raw_log_tail_is_bounded_and_read_only():
    source = Path("app/db/clickhouse.py").read_text(encoding="utf-8")
    router = Path("app/routers/raw_logs.py").read_text(encoding="utf-8")
    assert "FROM http_events FINAL" in source
    assert "LIMIT {max(1, min(int(limit), 500))}" in source
    assert "@router.get(\"/api/raw-logs/tail\")" in router
    assert "INSERT" not in router
