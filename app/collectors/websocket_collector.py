from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import inspect
import json
import logging
import os
import socket
from typing import Any
from urllib.parse import urlencode

from ..config import settings
from ..db import clickhouse as clickhouse_store
from ..db import postgres as postgres_store
from ..core import metrics
from ..db.repositories import CheckpointRepository
from ..core.logs import parse_apache_combined
from ..services.profiles import ensure_profile_postgres, refresh_due_profiles
from ..testing.failpoints import NoopFailpoint

logger = logging.getLogger(__name__)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class CollectorConfig:
    enabled: bool
    url: str
    token: str
    log_key: str
    source_id: str
    batch_size: int
    flush_ms: int
    ai_interval_seconds: int = 300

    @classmethod
    def from_env(cls) -> "CollectorConfig":
        enabled = os.getenv("LOG_WS_ENABLED", "false").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        return cls(
            enabled=enabled,
            url=os.getenv("LOG_WS_URL", "").strip(),
            token=os.getenv("LOG_WS_TOKEN", "").strip(),
            log_key=os.getenv("LOG_WS_LOG_KEY", "access").strip() or "access",
            source_id=os.getenv("LOG_WS_SOURCE_ID", "azure-access").strip()
            or "azure-access",
            batch_size=_env_int("LOG_WS_BATCH_SIZE", 200, 1),
            flush_ms=_env_int("LOG_WS_FLUSH_MS", 1000, 50),
            ai_interval_seconds=_env_int("LOG_WS_AI_INTERVAL_SECONDS", 300, 1),
        )

    @property
    def valid(self) -> bool:
        return bool(self.url and self.token and self.log_key and self.source_id)


class RealtimeBus:
    """Small process-local fanout bus used by the SSE endpoint."""

    def __init__(self) -> None:
        self._queues: set[asyncio.Queue[tuple[str, dict[str, Any]]]] = set()
        self._lock = asyncio.Lock()

    async def publish(self, event: str, payload: dict[str, Any]) -> None:
        async with self._lock:
            queues = tuple(self._queues)
        for queue in queues:
            try:
                queue.put_nowait((event, payload))
            except asyncio.QueueFull:
                pass

    async def subscribe(self):
        queue: asyncio.Queue[tuple[str, dict[str, Any]]] = asyncio.Queue(maxsize=100)
        async with self._lock:
            self._queues.add(queue)
        try:
            while True:
                yield await queue.get()
        finally:
            async with self._lock:
                self._queues.discard(queue)


bus = RealtimeBus()


def _env_int(name: str, default: int, minimum: int) -> int:
    try:
        return max(minimum, int(os.getenv(name, str(default))))
    except (TypeError, ValueError):
        return default


def trim_change_log(conn) -> None:
    conn.execute(
        "DELETE FROM ip_change_log WHERE seq <= "
        "(SELECT CASE WHEN MAX(seq) > 50000 THEN MAX(seq) - 50000 ELSE 0 END FROM ip_change_log)"
    )


class WebSocketCollector:
    def __init__(self, config: CollectorConfig | None = None) -> None:
        self.config = config or CollectorConfig.from_env()
        self.state = (
            "disabled"
            if not self.config.enabled
            else "config_error"
            if not self.config.valid
            else "connecting"
        )
        self.last_error: str | None = None
        self.last_offset = 0
        self.pending_lines = 0
        self.reconnect_attempt = 0
        self._stop = asyncio.Event()
        self._task: asyncio.Task | None = None
        self._flush_task: asyncio.Task | None = None
        self._enrichment_task: asyncio.Task | None = None
        self._privacy_task: asyncio.Task | None = None
        self._enrichment_queue: asyncio.Queue[str] = asyncio.Queue(maxsize=1000)
        self._enrichment_pending: set[str] = set()
        self._enrichment_deferred: set[str] = set()
        self._pending: list[tuple[str, str]] = []
        self._stream_offset = 0
        self._flush_lock = asyncio.Lock()
        self._owner = f"{socket.gethostname()}:{os.getpid()}"
        self.failpoint = NoopFailpoint()

    async def start(self) -> None:
        if self._task or not self.config.enabled or not self.config.valid:
            await self._publish_status()
            return
        self._stop.clear()
        self._task = asyncio.create_task(self.run(), name="websocket-collector")
        self._flush_task = asyncio.create_task(self._flush_loop(), name="websocket-flush")
        self._enrichment_task = asyncio.create_task(
            self.enrichment_loop(), name="websocket-enrichment"
        )
        self._privacy_task = asyncio.create_task(self.privacy_loop(), name="websocket-privacy-refresh")

    async def stop(self) -> None:
        self._stop.set()
        tasks = [
            task
            for task in (
                self._task,
                self._flush_task,
                self._enrichment_task,
                self._privacy_task,
            )
            if task
        ]
        if self._pending:
            await self._flush_pending()
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._task = self._flush_task = self._enrichment_task = self._privacy_task = None
        self.state = "stopped"
        await self._publish_status()

    def status(self) -> dict[str, Any]:
        metrics.gauge("collector.pending_lines", self.pending_lines)
        metrics.gauge("enrichment.queue_depth", self._enrichment_queue.qsize())
        metrics.gauge("collector.reconnect_attempt", self.reconnect_attempt)
        return {
            "enabled": self.config.enabled,
            "source_id": self.config.source_id,
            "log_key": self.config.log_key,
            "status": self.state,
            "last_offset": self.last_offset,
            "pending_lines": self.pending_lines,
            "reconnect_attempt": self.reconnect_attempt,
            "last_error": self.last_error,
            "last_ai_run": None,
            "ai_scoring": {},
            "ai_model_version": None,
            "ai_trained_at": None,
            "ai_train_status": None,
            "ai_training_windows": 0,
            "ai_last_score_at": None,
            "ai_score_status": None,
            "ai_last_error": None,
        }

    async def _publish_status(self) -> None:
        await asyncio.to_thread(self._persist_status)
        await bus.publish("collector_status", self.status())

    def _persist_status(self) -> None:
        CheckpointRepository().status(self.config.source_id, self.config.log_key, self.state, self.last_error)

    def _load_offset(self) -> int:
        self.last_offset = CheckpointRepository().load_offset(self.config.source_id, self.config.log_key)
        return self.last_offset

    def _acquire_lease(self) -> bool:
        return CheckpointRepository().acquire(self.config.source_id, self.config.log_key, self._owner, self.state)

    def _renew_lease(self) -> None:
        CheckpointRepository().renew(self.config.source_id, self._owner)

    async def _lease_loop(self) -> None:
        while not self._stop.is_set():
            await asyncio.sleep(10)
            await asyncio.to_thread(self._renew_lease)

    async def _flush_loop(self) -> None:
        interval = self.config.flush_ms / 1000
        while not self._stop.is_set():
            await asyncio.sleep(interval)
            await self._flush_pending()

    async def _flush_pending(self) -> int | None:
        async with self._flush_lock:
            if not self._pending:
                return None
            pending_entries = self._pending
            pending = [line for line, _received_at in pending_entries]
            received_at = min(stamp for _line, stamp in pending_entries)
            current_offset = max(self.last_offset, self._stream_offset)
            end_offset = current_offset + sum(
                len(line.encode("utf-8")) + 1 for line in pending
            )
            new_offset, cursor, affected, new_ips = await asyncio.to_thread(
                self._commit_batch, pending, end_offset, current_offset, received_at
            )
            self._pending = []
            self.pending_lines = 0
            self._stream_offset = new_offset
            self.last_offset = new_offset
            await self._after_commit(cursor, affected, new_ips)
            return new_offset

    def _connection_url(self, offset: int) -> str:
        separator = "&" if "?" in self.config.url else "?"
        query = urlencode(
            {
                "log": self.config.log_key,
                "offset": int(offset),
                "client": self.config.source_id,
                "clientId": self.config.source_id,
                "source_id": self.config.source_id,
            }
        )
        return self.config.url + separator + query

    def _connection_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.config.token}"}

    async def run(self) -> None:
        if not self.config.valid:
            self.state = "config_error"
            await self._publish_status()
            return
        try:
            import websockets
        except ImportError:
            self.state = "config_error"
            self.last_error = "websockets dependency is not installed"
            await self._publish_status()
            return

        await asyncio.to_thread(self._load_offset)
        backoff = 1.0
        while not self._stop.is_set():
            if not await asyncio.to_thread(self._acquire_lease):
                self.state = "standby"
                await self._publish_status()
                await asyncio.sleep(10)
                continue
            lease_task = asyncio.create_task(self._lease_loop(), name="websocket-lease")
            try:
                self.state = "connecting"
                await self._publish_status()
                offset = await asyncio.to_thread(self._load_offset)
                url = self._connection_url(offset)
                connect_options = {
                    "open_timeout": 30,
                    "ping_interval": 30,
                    "ping_timeout": 60,
                    "close_timeout": 10,
                    "max_size": 8 * 1024 * 1024,
                }
                header_argument = (
                    "additional_headers"
                    if "additional_headers" in inspect.signature(websockets.connect).parameters
                    else "extra_headers"
                )
                connect_options[header_argument] = self._connection_headers()
                async with websockets.connect(url, **connect_options) as websocket:
                    self.state = "backlog"
                    self.reconnect_attempt = 0
                    self.last_error = None
                    await self._publish_status()
                    async for raw in websocket:
                        if self._stop.is_set():
                            break
                        result = await self.handle_message(raw, offset)
                        if result is not None:
                            offset = result
                            self.last_offset = offset
                    backoff = 1.0
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.last_error = f"{type(exc).__name__}: {exc}"[:240]
                self.reconnect_attempt += 1
                metrics.increment("collector.reconnects")
                self.state = "retrying"
                await self._publish_status()
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 30.0)
            finally:
                lease_task.cancel()
                await asyncio.gather(lease_task, return_exceptions=True)

    async def handle_message(self, raw: str | None, current_offset: int) -> int | None:
        if raw is None:
            return None
        try:
            message = json.loads(raw)
        except (TypeError, json.JSONDecodeError):
            return None
        if not isinstance(message, dict):
            return None
        kind = message.get("type")
        if kind == "lines":
            items = message.get("items")
            flushed_offset: int | None = None
            if isinstance(items, list):
                async with self._flush_lock:
                    current_offset = max(current_offset, self._stream_offset)
                    self._stream_offset = current_offset
                    received_at = utc_now()
                    self._pending.extend(
                        (str(item), received_at) for item in items if isinstance(item, str)
                    )
                    self.pending_lines = len(self._pending)
                    while len(self._pending) >= self.config.batch_size:
                        batch_entries = self._pending[: self.config.batch_size]
                        self._pending = self._pending[self.config.batch_size :]
                        batch = [line for line, _received_at in batch_entries]
                        batch_received_at = min(stamp for _line, stamp in batch_entries)
                        end_offset = current_offset + sum(
                            len(line.encode("utf-8")) + 1 for line in batch
                        )
                        result = await asyncio.to_thread(
                            self._commit_batch, batch, end_offset, current_offset,
                            batch_received_at,
                        )
                        current_offset, cursor, affected, new_ips = result
                        self._stream_offset = current_offset
                        self.last_offset = current_offset
                        await self._after_commit(cursor, affected, new_ips)
                        flushed_offset = current_offset
                    self.pending_lines = len(self._pending)
            return flushed_offset
        if kind == "backlog_done":
            self.state = "live"
            await self._publish_status()
            return None
        if kind != "offset":
            return None
        try:
            end_offset = int(message["value"])
        except (KeyError, TypeError, ValueError):
            return None
        current_offset = max(current_offset, self._stream_offset)
        if end_offset < current_offset:
            return None
        async with self._flush_lock:
            pending_entries = self._pending
            pending = [line for line, _received_at in pending_entries]
            received_at = min(
                (stamp for _line, stamp in pending_entries), default=utc_now()
            )
            new_offset, cursor, affected, new_ips = await asyncio.to_thread(
                self._commit_batch, pending, end_offset, current_offset, received_at
            )
            self._pending = []
            self.pending_lines = 0
            self._stream_offset = new_offset
            self.last_offset = new_offset
            await self._after_commit(cursor, affected, new_ips)
            return new_offset

    async def _after_commit(
        self, cursor: int, affected: set[str], new_ips: list[str]
    ) -> None:
        for ip in new_ips:
            if ip in self._enrichment_pending:
                continue
            try:
                self._enrichment_queue.put_nowait(ip)
                self._enrichment_pending.add(ip)
            except asyncio.QueueFull:
                self._enrichment_pending.discard(ip)
                self._enrichment_deferred.add(ip)
                continue
        if affected and self.state == "live":
            await bus.publish(
                "ip_changes", {"cursor": int(cursor), "count": len(affected), "published_at": utc_now()}
            )

    def _commit_batch(
        self, lines: list[str], end_offset: int, current_offset: int,
        received_at: str | None = None,
    ) -> tuple[int, int, set[str], list[str]]:
        lengths = [len(line.encode("utf-8")) + 1 for line in lines]
        start_offset = max(current_offset, end_offset - sum(lengths))
        position = start_offset
        now = utc_now()
        events: list[dict[str, Any]] = []
        for line, length in zip(lines, lengths):
            event = parse_apache_combined(line)
            position += length
            if not event:
                continue
            offset = position - length
            source = f"ws:{self.config.source_id}"
            line_hash = hashlib.sha256(f"{source}\0{offset}\0{line}".encode()).hexdigest()
            events.append({
                **event,
                "dataset_id": settings.DATASET_LIVE_ID,
                "source_id": self.config.source_id,
                "source_offset": offset,
                "event_id": line_hash,
                "ingested_at": now,
                "pipeline_received_at": received_at or now,
                "raw_line": line,
            })
        if not events:
            return end_offset, 0, set(), []
        self.failpoint.hit("after_parse")
        clickhouse_store.insert_events(events)
        self.failpoint.hit("after_clickhouse_insert")
        from ..db.repositories import PgDetectionRepository
        batch_id = hashlib.sha256(f"{self.config.source_id}:{start_offset}:{end_offset}".encode()).hexdigest()
        result = PgDetectionRepository().process_events(
            events, batch_id, settings.DATASET_LIVE_ID, self.config.source_id,
            start_offset, end_offset, self.config.log_key, self.state,
            now=datetime.fromisoformat(now), failpoint=self.failpoint,
        )
        affected = set(result.get("affected", set()))
        with postgres_store.transaction() as conn:
            cursor = int(conn.execute("SELECT COALESCE(MAX(seq),0) AS seq FROM ip_change_log").fetchone()["seq"] or 0)
            profiles = conn.execute(
                "SELECT host(ip) AS ip FROM ip_profiles WHERE ip = ANY(%s::inet[])",
                (list(affected),),
            ).fetchall() if affected else []
        profiled = {str(row["ip"]) for row in profiles}
        self.failpoint.hit("before_ack")
        return end_offset, cursor, affected, sorted(affected - profiled)

    @staticmethod
    def _enrich_one(ip: str) -> tuple[str, bool, str | None]:
        try:
            data, error = asyncio.run(ensure_profile_postgres(ip))
            return ip, bool(data and not error), error
        except Exception as exc:
            return ip, False, f"{type(exc).__name__}: {exc}"

    async def enrichment_loop(self) -> None:
        concurrency = _env_int("ENRICHMENT_CONCURRENCY", 4, 1)
        batch_size = _env_int("ENRICHMENT_BATCH_SIZE", 20, 1)
        while not self._stop.is_set():
            try:
                first = await asyncio.wait_for(self._enrichment_queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                first = None
            batch = []
            if first:
                batch.append(first)
            while len(batch) < batch_size:
                try:
                    batch.append(self._enrichment_queue.get_nowait())
                except asyncio.QueueEmpty:
                    break
            deferred = list(self._enrichment_deferred)
            self._enrichment_deferred.clear()
            capacity = max(0, batch_size - len(batch))
            batch.extend(deferred[:capacity])
            self._enrichment_deferred.update(deferred[capacity:])
            batch = list(dict.fromkeys(batch))
            if not batch:
                continue
            for ip in batch:
                self._enrichment_pending.discard(ip)
            results = []
            for start in range(0, len(batch), concurrency):
                results.extend(await asyncio.gather(*[
                    asyncio.to_thread(self._enrich_one, ip)
                    for ip in batch[start:start + concurrency]
                ]))
            successful = [ip for ip, ok, _error in results if ok]
            if successful:
                with postgres_store.transaction() as pg_conn:
                    now = datetime.now(timezone.utc)
                    for ip in successful:
                        pg_conn.execute(
                            "INSERT INTO ip_change_log(dataset_id,ip,reason,changed_at) VALUES(%s,%s,'enrichment',%s)",
                            (settings.DATASET_LIVE_ID, ip, now),
                        )
                    trim_change_log(pg_conn)
                    cursor = int(pg_conn.execute("SELECT COALESCE(MAX(seq),0) AS seq FROM ip_change_log").fetchone()["seq"] or 0)
                await bus.publish("ip_changes", {"cursor": cursor, "count": len(successful), "published_at": utc_now()})

    async def privacy_loop(self) -> None:
        interval = _env_int("LOG_WS_PRIVACY_REFRESH_INTERVAL_SECONDS", 3600, 60)
        while not self._stop.is_set():
            await asyncio.sleep(interval)
            try:
                result = await refresh_due_profiles(
                    None, limit=_env_int("PRIVACY_REFRESH_BATCH", 100, 1)
                )
                if result.get("processed"):
                    await bus.publish(
                        "ip_changes", {"cursor": 0, "count": result["processed"], "published_at": utc_now()}
                    )
            except asyncio.CancelledError:
                raise
            except Exception:
                pass


collector = WebSocketCollector()
