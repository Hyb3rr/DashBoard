import asyncio
import json

from fastapi import APIRouter
from fastapi.responses import StreamingResponse

from ..collectors.websocket_collector import bus, collector
from ..services.profiles import ensure_profile_postgres
from ..db import postgres as postgres_store

router = APIRouter()


@router.get("/api/collector/status")
def collector_status():
    payload = collector.status()
    payload["ai_state_backend"] = "postgresql_live_only"
    return payload


@router.post("/api/ips/refresh-unknown")
async def refresh_unknown(limit: int = 500):
    limit = min(max(limit, 1), 5000)
    with postgres_store.transaction() as pg_conn:
        rows = pg_conn.execute("""SELECT host(o.ip) AS ip
            FROM ip_observations_state o LEFT JOIN ip_profiles p ON p.ip=o.ip
            WHERE p.ip IS NULL OR p.enrichment_status IS DISTINCT FROM 'complete'
               OR p.country IS NULL OR p.country_code IS NULL
            ORDER BY COALESCE(NULLIF(o.payload->>'requests','')::bigint,0) DESC, o.ip ASC
            LIMIT %s""", (limit,)).fetchall()
    selected = [str(row["ip"]) for row in rows]

    async def generate_split():
        yield json.dumps({"type": "start", "selected": len(selected), "mode": "live", "order": "requests_desc"}) + "\n"
        processed = complete = partial = failed = 0
        for ip in selected:
            data, error = await ensure_profile_postgres(ip, refresh=True)
            processed += 1
            if data and not error:
                complete += 1
                status = "complete"
            elif data:
                partial += 1
                status = "partial"
            else:
                failed += 1
                status = "failed"
            yield json.dumps({"type": "item", "ip": ip, "status": status, "error": error}) + "\n"
        yield json.dumps({"type": "done", "selected": len(selected), "processed": processed, "complete": complete, "partial": partial, "failed": failed}) + "\n"

    return StreamingResponse(generate_split(), media_type="application/x-ndjson", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@router.get("/api/stream")
async def realtime_stream():
    async def generate():
        iterator = bus.subscribe().__aiter__()
        try:
            while True:
                try:
                    event, payload = await asyncio.wait_for(iterator.__anext__(), timeout=15)
                    yield f"event: {event}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"
                except asyncio.TimeoutError:
                    yield ": heartbeat\n\n"
        except (asyncio.CancelledError, StopAsyncIteration):
            return
        finally:
            await iterator.aclose()

    return StreamingResponse(generate(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
