from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import HTMLResponse

from ..config.settings import TEMPLATES_DIR
from ..db.ai_trigger import AiTriggerRepository
from ..db.repositories import AlertRepository


router = APIRouter()
AUTO_EXPLAIN_SETTING = "critical_alert_auto_explain"


@router.get("/alerts", response_class=HTMLResponse)
def alerts_page():
    return HTMLResponse((TEMPLATES_DIR / "alerts.html").read_text(encoding="utf-8"))


def _iso(value):
    return value.isoformat() if hasattr(value, "isoformat") else value


def _item(row: dict) -> dict:
    result = dict(row)
    for key in ("created_at", "updated_at", "acknowledged_at", "resolved_at"):
        result[key] = _iso(result.get(key))
    result["ip"] = str(result["ip"])
    return result


@router.get("/api/alerts/settings")
def get_alert_settings():
    return {"critical_alert_auto_explain": AiTriggerRepository().auto_explain_enabled()}


@router.patch("/api/alerts/settings")
def update_alert_settings(payload: dict):
    if not isinstance(payload, dict) or not isinstance(payload.get(AUTO_EXPLAIN_SETTING), bool):
        raise HTTPException(status_code=400, detail=f"{AUTO_EXPLAIN_SETTING} must be boolean")
    enabled = AiTriggerRepository().set_auto_explain_enabled(payload[AUTO_EXPLAIN_SETTING])
    return {"critical_alert_auto_explain": enabled}


@router.get("/api/alerts")
def list_alerts(
    severity: str | None = Query(default=None),
    status: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
):
    result = AlertRepository().list(severity, status, limit, offset)
    return {"items": [_item(row) for row in result["items"]], "total": result["total"], "limit": limit, "offset": offset}


@router.patch("/api/alerts/{alert_id}")
def update_alert(alert_id: int, payload: dict):
    status = payload.get("status") if isinstance(payload, dict) else None
    if status not in {"acknowledged", "resolved"}:
        raise HTTPException(status_code=400, detail="status must be acknowledged or resolved")
    row = AlertRepository().set_status(alert_id, status)
    if not row:
        raise HTTPException(status_code=404, detail="alert not found")
    return _item(row)
