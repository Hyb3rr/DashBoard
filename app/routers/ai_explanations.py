"""Manual AI explanation request boundary; inference is handled later by a worker."""

from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ..db.ai_jobs import AiExplainJobRepository
from ..db import clickhouse as clickhouse_store
from ..db.repositories import StateRepository
from ..services.case_packets import build_live_case_packet
from .ip_state import _pg_item


router = APIRouter()


class ExplainRequest(BaseModel):
    evidence_fingerprint: str | None = None


def _iso(value):
    return value.isoformat() if hasattr(value, "isoformat") else value


def _job_response(job: dict) -> dict:
    completed = job.get("status") == "completed" and job.get("validation_status") == "validated"
    return {
        "job_id": job["job_id"], "case_id": job["case_id"],
        "evidence_fingerprint": job["evidence_fingerprint"],
        "status": job["status"], "validation_status": job.get("validation_status"),
        "requested_at": _iso(job.get("requested_at")),
        "started_at": _iso(job.get("started_at")), "completed_at": _iso(job.get("completed_at")),
        "failure_code": job.get("failure_code"),
        "analysis": job.get("analysis_json") if completed else None,
        "validation": job.get("validation_json") if completed else None,
        "provenance": job.get("provenance_json") if completed else None,
    }


@router.post("/api/ai/cases/{case_id}/explain", status_code=202)
def request_explanation(case_id: str, request: ExplainRequest):
    identity = case_id.strip()
    if not identity:
        raise HTTPException(status_code=400, detail="case_id is required")
    packet = None
    fingerprint = (request.evidence_fingerprint or "").strip()
    try:
        address = ipaddress.ip_address(identity)
    except ValueError:
        address = None
    if address and not fingerprint:
        row = StateRepository().get(str(address))
        if not row:
            raise HTTPException(status_code=404, detail="IP not found")
        snapshot = _pg_item(row)
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=1)
        try:
            traffic = clickhouse_store.traffic_for_ip(start, end, 3600, str(address), "live")
        except Exception as exc:
            raise HTTPException(status_code=503, detail="Live traffic snapshot unavailable") from exc
        packet = build_live_case_packet(str(address), snapshot, traffic, start.isoformat(), end.isoformat())
        identity, fingerprint = packet["case_id"], packet["evidence_fingerprint"]
    if not fingerprint:
        raise HTTPException(status_code=400, detail="evidence_fingerprint is required for non-IP cases")
    try:
        repository = AiExplainJobRepository()
        job = repository.create_or_get(identity, fingerprint, packet) if packet is not None else repository.create_or_get(identity, fingerprint)
    except (OSError, RuntimeError) as exc:
        raise HTTPException(status_code=503, detail="AI job storage unavailable") from exc
    return {
        "job_id": job["job_id"], "case_id": job["case_id"],
        "evidence_fingerprint": job["evidence_fingerprint"],
        "status": job["status"], "accepted": True,
    }


@router.get("/api/ai/jobs/{job_id}")
def get_explanation_job(job_id: str):
    if not job_id.strip():
        raise HTTPException(status_code=400, detail="job_id is required")
    try:
        job = AiExplainJobRepository().get(job_id.strip())
    except (OSError, RuntimeError) as exc:
        raise HTTPException(status_code=503, detail="AI job storage unavailable") from exc
    if not job:
        raise HTTPException(status_code=404, detail="AI job not found")
    return _job_response(job)
