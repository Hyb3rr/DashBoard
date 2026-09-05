from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import asyncio
import time
from .config.settings import STATIC_DIR
from .services.classification_watcher import run_classification_watcher
from .services.coverage import run_coverage_consumer
from .services.ai_runtime import ai_runtime
from .collectors.websocket_collector import collector
from .db import postgres as postgres_store
from .routers.realtime import router as realtime_router
from .routers.pages import router as pages_router
from .routers.health import router as health_router
from .routers.traffic import router as traffic_router
from .routers.ip_state import router as ip_state_router
from .routers.ip_detail import router as ip_detail_router
from .routers.regions import router as regions_router
from .routers.map_intelligence import router as map_intelligence_router
from .routers.ai_explanations import router as ai_explanations_router
from .routers.alerts import router as alerts_router


@asynccontextmanager
async def lifespan(_app: FastAPI):
    postgres_store.open_pool()
    await collector.start()
    await ai_runtime.start()
    watcher = asyncio.create_task(run_classification_watcher())
    coverage = asyncio.create_task(run_coverage_consumer())
    try:
        yield
    finally:
        watcher.cancel()
        coverage.cancel()
        await asyncio.gather(watcher, coverage, return_exceptions=True)
        try:
            await ai_runtime.stop()
            await collector.stop()
        finally:
            postgres_store.close_pool()


app = FastAPI(title="Remote Web Monitoring Hub - IP Intelligence", lifespan=lifespan)
app.include_router(health_router)
app.include_router(traffic_router)
app.include_router(ip_state_router)
app.include_router(ip_detail_router)
app.include_router(regions_router)
app.include_router(map_intelligence_router)
app.include_router(ai_explanations_router)
app.include_router(alerts_router)
app.include_router(realtime_router)
app.include_router(pages_router)


@app.middleware("http")
async def timing_middleware(request, call_next):
    started = time.perf_counter()
    response = await call_next(request)
    response.headers["X-Process-Time-ms"] = f"{(time.perf_counter() - started) * 1000:.1f}"
    return response


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8000", "http://localhost:8000", "null"],
    allow_origin_regex=r"^(null|https?://(localhost|127\.0\.0\.1)(:\d+)?)$",
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)
