from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import asyncio
import os
import time
import threading
from .config.settings import APP_DIR
from .services.classification_watcher import run_classification_watcher
from .services.coverage import run_coverage_consumer
from .collectors.websocket_collector import collector
from .core.intel_updater import run_due_sources
from .db import clickhouse as clickhouse_store
from .db import postgres as postgres_store
from .db.repositories import RegionRepository
from .routers.realtime import router as realtime_router
from .routers.pages import router as pages_router
from .routers.health import router as health_router
from .routers.traffic import router as traffic_router
from .routers.ip_state import _pg_item, router as ip_state_router
from .routers.ip_detail import router as ip_detail_router
from .routers.regions import router as regions_router


@asynccontextmanager
async def lifespan(_app: FastAPI):
    postgres_store.open_pool()
    postgres_store.ensure_schema()
    clickhouse_store.ensure_schema()
    await collector.start()
    watcher = asyncio.create_task(run_classification_watcher())
    coverage = asyncio.create_task(run_coverage_consumer())
    if os.getenv("INTEL_AUTO_UPDATE_ON_STARTUP", "false").strip().lower() in {"1", "true", "yes", "on"}:
        # Remote provider downloads have no reliable cancellation point. Keep
        # this best-effort job outside the server's asyncio default executor so
        # graceful shutdown never waits indefinitely on a remote socket.
        threading.Thread(target=run_due_sources, name="intel-startup-update", daemon=True).start()
    try:
        yield
    finally:
        watcher.cancel()
        coverage.cancel()
        await asyncio.gather(watcher, coverage, return_exceptions=True)
        try:
            await collector.stop()
        finally:
            postgres_store.close_pool()


app = FastAPI(title="Remote Web Monitoring Hub - IP Intelligence", lifespan=lifespan)
app.include_router(health_router)
app.include_router(traffic_router)
app.include_router(ip_state_router)
app.include_router(ip_detail_router)
app.include_router(regions_router)
app.include_router(realtime_router)
app.include_router(pages_router)


@app.middleware("http")
async def timing_middleware(request, call_next):
    started = time.perf_counter()
    response = await call_next(request)
    response.headers["X-Process-Time-ms"] = f"{(time.perf_counter() - started) * 1000:.1f}"
    return response


app.mount("/static", StaticFiles(directory=APP_DIR / "static"), name="static")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8000", "http://localhost:8000", "null"],
    allow_origin_regex=r"^(null|https?://(localhost|127\.0\.0\.1)(:\d+)?)$",
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)
