from pathlib import Path


def test_enrichment_queue_is_durable_and_worker_role_owned():
    root = Path(__file__).parents[1]
    migration = (root / "infra/postgres/037_enrichment_requests.sql").read_text()
    source = (root / "app/routers/ip_detail.py").read_text()
    main = (root / "app/main.py").read_text()
    assert "CREATE TABLE IF NOT EXISTS enrichment_requests" in migration
    assert "FOR UPDATE SKIP LOCKED" in (root / "app/services/enrichment_queue.py").read_text()
    assert "enqueue, address_text" in source
    assert "run_enrichment_worker" in main
    assert "collector.schedule_enrichment" not in source
