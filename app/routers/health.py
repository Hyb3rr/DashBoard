from fastapi import APIRouter

from .. import config
from ..collectors.websocket_collector import collector
from ..core.rules import ruleset_health
from ..core.metrics import snapshot as metrics_snapshot
from ..db import clickhouse as clickhouse_store
from ..db import postgres as postgres_store
from ..db.repositories import AiRepository

router = APIRouter()


@router.get("/health")
def health():
    rules_health = ruleset_health()
    collector_info = collector.status() if collector else {"status": "disabled"}
    storage = {"backend": config.settings.DATA_BACKEND, "postgres": postgres_store.health(), "clickhouse": clickhouse_store.health()}
    ai_state = AiRepository().state("isolation_forest_v1")
    ai_status = "pending"
    if ai_state:
        if ai_state.get("model_version") and ai_state.get("last_score_status") == "scored":
            ai_status = "ready"
        elif ai_state.get("last_train_status") == "failed" or ai_state.get("last_score_status") == "failed":
            ai_status = "error"
        elif ai_state.get("last_train_status") == "insufficient_data":
            ai_status = "unavailable"
    ai = {
        "status": ai_status,
        "state": ai_state,
        "summary": AiRepository().summary(),
    }
    healthy = rules_health["status"] == "ok" and all(
        item.get("status") == "ok" for item in storage.values() if isinstance(item, dict) and "status" in item
    )
    return {"status": "ok" if healthy else "degraded", "mode": config.settings.DATA_BACKEND,
            "rules": rules_health, "storage": storage, "collector": collector_info,
            "workload": collector_info.get("workload", {}) if isinstance(collector_info, dict) else {},
            "ai": ai, "observability": metrics_snapshot()}
