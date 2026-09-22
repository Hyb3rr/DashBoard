import logging
from contextlib import asynccontextmanager

# clickhouse_connect logs WARNING on every keep-alive reset even when the
# built-in retry succeeds.  Lift to ERROR so only real failures surface.
logging.getLogger("clickhouse_connect.driver.httpclient").setLevel(logging.ERROR)

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.gzip import GZipMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
import asyncio
import time
from .config.settings import APP_ROLE, AUTH_IDENTITY_HEADER, AUTH_REQUIRED, AUTH_ROLE_HEADER, AUTH_TRUSTED_PROXY_NETWORKS, SECURITY_HEADERS_ENABLED, STATIC_DIR, TRUSTED_HOSTS
from .core.authorization import has_role, parse_roles, required_role
from .core.proxy_auth import valid_proxy_identity
from .core.request_context import request_id
from .core import metrics
from .services.classification_watcher import run_classification_watcher
from .services.coverage import run_coverage_consumer
from .services.enrichment_queue import run_enrichment_worker
from .services.ai_runtime import ai_runtime
from .services.realtime_listener import PostgresRealtimeListener
from .collectors.websocket_collector import bus, collector
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
from .routers.behavior_events import router as behavior_events_router
from .routers.raw_logs import router as raw_logs_router


@asynccontextmanager
async def lifespan(_app: FastAPI):
    postgres_store.open_pool()
    realtime_listener = PostgresRealtimeListener(bus.publish)
    _app.state.realtime_listener = realtime_listener
    collector_task = None
    ai_started = False
    watcher = None
    coverage = None
    enrichment = None
    enrichment_stop = asyncio.Event()
    if APP_ROLE in {"all", "collector"}:
        await collector.start()
        collector_task = collector
    if APP_ROLE in {"all", "ai"}:
        await ai_runtime.start()
        ai_started = True
    if APP_ROLE in {"all", "api"}:
        await realtime_listener.start()
    if APP_ROLE in {"all", "worker"}:
        watcher = asyncio.create_task(run_classification_watcher())
        coverage = asyncio.create_task(run_coverage_consumer())
        enrichment = asyncio.create_task(run_enrichment_worker(enrichment_stop))
    try:
        yield
    finally:
        enrichment_stop.set()
        for task in (watcher, coverage, enrichment):
            if task is not None:
                task.cancel()
        tasks = [task for task in (watcher, coverage, enrichment) if task is not None]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        try:
            if ai_started:
                await ai_runtime.stop()
            await realtime_listener.stop()
            if collector_task is not None:
                await collector_task.stop()
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
app.include_router(behavior_events_router)
app.include_router(raw_logs_router)
app.include_router(realtime_router)
app.include_router(pages_router)


@app.middleware("http")
async def timing_middleware(request, call_next):
    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        metrics.increment("http.errors")
        raise
    elapsed_ms = (time.perf_counter() - started) * 1000
    metrics.increment("http.requests")
    metrics.observe("http.request_ms", elapsed_ms)
    response.headers["X-Process-Time-ms"] = f"{elapsed_ms:.1f}"
    return response


@app.middleware("http")
async def request_context_middleware(request, call_next):
    correlation_id = request_id(request.headers.get("X-Request-ID"))
    request.state.request_id = correlation_id
    response = await call_next(request)
    response.headers["X-Request-ID"] = correlation_id
    return response


@app.middleware("http")
async def security_headers_middleware(request, call_next):
    response = await call_next(request)
    if SECURITY_HEADERS_ENABLED:
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    return response


@app.middleware("http")
async def reverse_proxy_auth(request: Request, call_next):
    if not AUTH_REQUIRED or request.url.path == "/livez" or request.url.path.startswith("/static/"):
        return await call_next(request)
    peer = request.client.host if request.client else None
    identity = request.headers.get(AUTH_IDENTITY_HEADER)
    if not valid_proxy_identity(peer, identity, AUTH_TRUSTED_PROXY_NETWORKS):
        return JSONResponse({"detail": "Authentication required"}, status_code=401)
    request.state.auth_identity = identity.strip()
    roles = parse_roles(request.headers.get(AUTH_ROLE_HEADER))
    request.state.auth_roles = roles
    required = required_role(request.method, request.url.path)
    if required and not has_role(roles, required):
        return JSONResponse({"detail": "Insufficient role"}, status_code=403)
    return await call_next(request)


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8000", "http://localhost:8000", "null"],
    allow_origin_regex=r"^(null|https?://(localhost|127\.0\.0\.1)(:\d+)?)$",
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)
app.add_middleware(GZipMiddleware, minimum_size=1024, compresslevel=5)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(TRUSTED_HOSTS))
