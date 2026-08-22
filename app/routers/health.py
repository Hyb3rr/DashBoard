from fastapi import APIRouter

from .. import config
from ..collectors.websocket_collector import collector
from ..core.rules import ruleset_health
from ..core.metrics import snapshot as metrics_snapshot
from ..db import clickhouse as clickhouse_store
from ..db import postgres as postgres_store

router = APIRouter()


@router.get("/health")
def health():
    rules_health = ruleset_health()
    collector_info = collector.status() if collector else {"status": "disabled"}
    storage = {"backend": config.settings.DATA_BACKEND, "postgres": postgres_store.health(), "clickhouse": clickhouse_store.health()}
    healthy = rules_health["status"] == "ok" and all(
        item.get("status") == "ok" for item in storage.values() if isinstance(item, dict) and "status" in item
    )
    return {"status": "ok" if healthy else "degraded", "mode": config.settings.DATA_BACKEND,
            "rules": rules_health, "storage": storage, "collector": collector_info,
            "observability": metrics_snapshot()}
