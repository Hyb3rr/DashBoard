from fastapi import APIRouter, Request
from fastapi.responses import PlainTextResponse

from .. import config
from ..collectors.websocket_collector import collector
from ..core.rules import ruleset_health
from ..core.metrics import prometheus_text, snapshot as metrics_snapshot
from ..db import clickhouse as clickhouse_store
from ..db import postgres as postgres_store
from ..db.repositories import AiRepository
from ..services import classification_watcher

router = APIRouter()


def _collector_is_healthy(collector_info: dict) -> bool:
    """Check collector task, archive, parser, privacy, and shared-state health."""
    if not collector_info.get("enabled"):
        return True
    unhealthy_tasks = {"failed", "stopped", "cancelled"}
    if any(value in unhealthy_tasks for value in collector_info.get("tasks", {}).values()):
        return False
    if collector_info.get("raw_archive", {}).get("writer_status") == "FAILED":
        return False
    if collector_info.get("parser", {}).get("status") == "degraded":
        return False
    if collector_info.get("privacy_refresh", {}).get("status") == "failed":
        return False
    return not collector_info.get("control_plane_stale")


def _system_is_healthy(rules_health: dict, storage: dict, collector_info: dict,
                       watcher_info: dict, realtime_info: dict, app_role: str) -> bool:
    """Combine subsystem readiness using the existing API health policy."""
    healthy = rules_health["status"] == "ok" and all(
        item.get("status") == "ok" for item in storage.values() if isinstance(item, dict) and "status" in item
    )
    healthy = healthy and _collector_is_healthy(collector_info)
    healthy = healthy and watcher_info.get("status") != "retrying"
    if app_role in {"all", "api"} and realtime_info.get("status") not in {"running", "disabled"}:
        healthy = False
    return healthy


@router.get("/livez")
def livez():
    """Minimal unauthenticated process liveness probe for a load balancer."""
    return {"status": "ok"}


@router.get("/metrics", response_class=PlainTextResponse)
def metrics_endpoint():
    """Prometheus-compatible process metrics; auth is enforced by middleware."""
    return PlainTextResponse(prometheus_text(), media_type="text/plain; version=0.0.4")


@router.get("/health")
def health(request: Request):
    """Report detailed health across storage, collector, rules, workers, and AI."""
    rules_health = ruleset_health()
    collector_info = collector.shared_status() if collector else {"status": "disabled"}
    watcher_info = classification_watcher.status()
    realtime_listener = getattr(request.app.state, "realtime_listener", None)
    realtime_info = realtime_listener.status() if realtime_listener else {"status": "not_started", "failures": 0, "last_error": None}
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
    healthy = _system_is_healthy(
        rules_health, storage, collector_info, watcher_info, realtime_info, config.settings.APP_ROLE
    )
    return {"status": "ok" if healthy else "degraded", "mode": config.settings.DATA_BACKEND,
            "rules": rules_health, "storage": storage, "collector": collector_info,
            "classification_watcher": watcher_info,
            "realtime_listener": realtime_info,
            "workload": collector_info.get("workload", {}) if isinstance(collector_info, dict) else {},
            "ai": ai, "observability": metrics_snapshot()}
