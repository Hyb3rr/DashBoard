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
import time
from typing import Any
from urllib.parse import urlencode

from ..config import settings
from ..db import clickhouse as clickhouse_store
from ..db import postgres as postgres_store
from ..core import metrics
from ..db.repositories import CheckpointRepository
from ..db.repositories import CheckpointCommitRejected
from ..core.logs import PARSER_VERSION, parse_apache_combined_diagnostic
from ..core.fast_detection import ShortWindowDetector
from ..services.profiles import ensure_profile_postgres, refresh_due_profiles
from ..services.rare_path_detector import periodic_shadow
from ..services.early_alerts import early_alerts
from ..services.workload_governor import WorkloadGovernor
from ..services.ai_runtime import ai_runtime
from ..services.raw_log_archive import RawLogArchive
from ..core.failpoints import NoopFailpoint

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
            ai_interval_seconds=_env_int("AI_RUNTIME_INTERVAL_SECONDS", 300, 1),
        )

    @property
    def valid(self) -> bool:
        return bool(self.url and self.token and self.log_key and self.source_id)


class _StorageStop:
    """Private queue marker used only after all accepted storage work drains."""


_STORAGE_STOP = _StorageStop()


class RealtimeBus:
    """Small process-local fanout bus used by the SSE endpoint."""

    def __init__(self) -> None:
        self._subscriptions: set[_RealtimeSubscription] = set()
        self._lock = asyncio.Lock()

    async def publish(self, event: str, payload: dict[str, Any]) -> None:
        async with self._lock:
            for subscription in tuple(self._subscriptions):
                if event == "ip_changes" and subscription.ip_changes_pending:
                    # Cursor notifications are wake-ups, not durable events.
                    # Keep only the newest cursor while a client is consuming.
                    subscription.latest_ip_changes = payload
                    continue
                try:
                    subscription.queue.put_nowait((event, payload))
                except asyncio.QueueFull:
                    metrics.increment("realtime_bus_dropped_events")
                    continue
                if event == "ip_changes":
                    subscription.ip_changes_pending = True

    async def subscribe(self):
        subscription = _RealtimeSubscription()
        async with self._lock:
            self._subscriptions.add(subscription)
        try:
            while True:
                event, payload = await subscription.queue.get()
                yield event, payload
                if event == "ip_changes":
                    async with self._lock:
                        if subscription.latest_ip_changes is None:
                            subscription.ip_changes_pending = False
                        else:
                            latest = subscription.latest_ip_changes
                            subscription.latest_ip_changes = None
                            subscription.queue.put_nowait(("ip_changes", latest))
        finally:
            async with self._lock:
                self._subscriptions.discard(subscription)


class _RealtimeSubscription:
    def __init__(self) -> None:
        self.queue: asyncio.Queue[tuple[str, dict[str, Any]]] = asyncio.Queue(maxsize=100)
        self.ip_changes_pending = False
        self.latest_ip_changes: dict[str, Any] | None = None


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
        self._lease_lost = asyncio.Event()
        self._active_websocket = None
        self._task: asyncio.Task | None = None
        self._flush_task: asyncio.Task | None = None
        self._storage_task: asyncio.Task | None = None
        self._enrichment_task: asyncio.Task | None = None
        self._privacy_task: asyncio.Task | None = None
        self._rare_path_task: asyncio.Task | None = None
        self._enrichment_queue: asyncio.Queue[str] = asyncio.Queue(maxsize=1000)
        self._enrichment_pending: set[str] = set()
        self._enrichment_deferred: set[str] = set()
        self._pending: list[tuple[str, str]] = []
        self._storage_queue: asyncio.Queue[tuple[list[str], int, int, str]] = asyncio.Queue(maxsize=1000)
        self._window_detector = ShortWindowDetector()
        self._governor = WorkloadGovernor()
        self._storage_oldest_started: float | None = None
        self._parser_accepted_lines = 0
        self._parser_rejected_lines = 0
        self._parser_consecutive_reject_batches = 0
        self._parser_last_rejection_ratio = 0.0
        self._privacy_failures = 0
        self._privacy_last_error: str | None = None
        self._stream_offset = 0
        self._flush_lock = asyncio.Lock()
        self._owner = f"{socket.gethostname()}:{os.getpid()}"
        self._supervisor_backoff = 1.0
        self.failpoint = NoopFailpoint()
        self._raw_archive = RawLogArchive(self.config.source_id)
        self._clickhouse_writer = clickhouse_store.ClickHouseWriter()

    async def start(self) -> None:
        if os.getenv("RARE_PATH_ENABLED", "true").strip().lower() in {"1", "true", "yes", "on"}:
            self._rare_path_task = asyncio.create_task(
                periodic_shadow(self._stop, on_changed=self._publish_rare_changes,
                                should_run=self._governor.allow_rare_path),
                name="rare-path-shadow",
            )
        if self._task and not self._task.done():
            await self._publish_status()
            return
        if self._task and self._task.done():
            try:
                self._task.exception()
            except asyncio.CancelledError:
                pass
            self._task = None
        self._stop.clear()
        await self._raw_archive.start()

        # Enrichment is also requested by the IP detail API. It must remain
        # available when websocket ingestion is disabled (the default for a
        # local/demo deployment), otherwise those requests accumulate forever
        # in the queue with no worker to process them.
        self._enrichment_task = asyncio.create_task(
            self.enrichment_loop(), name="websocket-enrichment"
        )
        self._privacy_task = asyncio.create_task(self.privacy_loop(), name="websocket-privacy-refresh")
        await early_alerts.start()
        if self.config.enabled and self.config.valid:
            self._task = asyncio.create_task(self._supervise_run(), name="websocket-collector")
            self._flush_task = asyncio.create_task(self._flush_loop(), name="websocket-flush")
            self._ensure_storage_worker()
        else:
            self.state = "disabled" if not self.config.enabled else "config_error"
        await self._publish_status()

    async def stop(self) -> None:
        self._stop.set()
        producer_tasks = [
            task
            for task in (
                self._task,
                self._flush_task,
                self._enrichment_task,
                self._privacy_task,
                self._rare_path_task,
            )
            if task
        ]
        for task in producer_tasks:
            task.cancel()
        if producer_tasks:
            await asyncio.gather(*producer_tasks, return_exceptions=True)
        if self._pending:
            await self._flush_pending()
        if self._storage_task and not self._storage_task.done():
            await self._storage_queue.join()
            await self._storage_queue.put(_STORAGE_STOP)
            await self._storage_task
        elif self._storage_task:
            self._discard_uncommitted_storage()
        await self._raw_archive.stop()
        self._clickhouse_writer.close()
        self._task = self._flush_task = self._storage_task = self._enrichment_task = self._privacy_task = self._rare_path_task = None
        await early_alerts.stop()
        self.state = "stopped"
        await self._publish_status()

    def status(self) -> dict[str, Any]:
        metrics.gauge("collector.pending_lines", self.pending_lines)
        metrics.gauge("enrichment.queue_depth", self._enrichment_queue.qsize())
        oldest_age_ms = 0.0
        if self._storage_oldest_started is not None:
            oldest_age_ms = (time.monotonic() - self._storage_oldest_started) * 1000
        state = self._governor.update(
            self._storage_queue.qsize(), oldest_age_ms, early_alerts.status()["queue_depth"]
        )
        metrics.gauge("storage.queue_depth", self._storage_queue.qsize())
        metrics.gauge("storage.oldest_age_ms", oldest_age_ms)
        metrics.gauge("collector.reconnect_attempt", self.reconnect_attempt)
        raw_archive = self._raw_archive.status()
        tasks = {
            "run": self._task_status(self._task),
            "flush": self._task_status(self._flush_task),
            "storage": self._task_status(self._storage_task),
            "enrichment": self._task_status(self._enrichment_task),
            "privacy": self._task_status(self._privacy_task),
            "raw_writer": raw_archive.get("writer_status", "unknown"),
        }
        parser = {
            "accepted_lines": self._parser_accepted_lines,
            "rejected_lines": self._parser_rejected_lines,
            "last_rejection_ratio": self._parser_last_rejection_ratio,
            "consecutive_reject_batches": self._parser_consecutive_reject_batches,
            "status": "degraded" if self._parser_consecutive_reject_batches >= 3 else "ok",
        }
        return {
            "enabled": self.config.enabled,
            "source_id": self.config.source_id,
            "log_key": self.config.log_key,
            "status": self.state,
            "last_offset": self.last_offset,
            "pending_lines": self.pending_lines,
            "reconnect_attempt": self.reconnect_attempt,
            "last_error": self.last_error,
            "tasks": tasks,
            "workload": {
                "mode": state.mode,
                "storage_queue_depth": state.storage_queue_depth,
                "storage_oldest_age_ms": state.storage_oldest_age_ms,
                "early_alert_queue_depth": state.early_alert_queue_depth,
            },
            "raw_archive": raw_archive,
            "parser": parser,
            "privacy_refresh": {
                "status": "failed" if self._privacy_failures else "ok",
                "consecutive_failures": self._privacy_failures,
                "last_error": self._privacy_last_error,
            },
            "ai_runtime": ai_runtime.status(),
        }

    def shared_status(self) -> dict[str, Any]:
        """Use persisted control-plane state when this process is API-only."""
        local = self.status()
        if any(value == "running" for value in local.get("tasks", {}).values()):
            return local
        persisted = CheckpointRepository().read_status(self.config.source_id)
        if not persisted:
            return local
        lease_expires_at = persisted.get("lease_expires_at")
        lease_expired = bool(
            lease_expires_at
            and lease_expires_at <= datetime.now(timezone.utc)
        )
        local.update({
            "enabled": True,
            "status": persisted.get("status") or "unknown",
            "source_id": persisted.get("source_id") or self.config.source_id,
            "log_key": persisted.get("log_key") or self.config.log_key,
            "last_offset": int(persisted.get("last_offset") or 0),
            "last_error": persisted.get("last_error"),
            "shared_control_plane": True,
            "updated_at": persisted.get("updated_at").isoformat() if hasattr(persisted.get("updated_at"), "isoformat") else persisted.get("updated_at"),
            "last_event_at": persisted.get("last_event_at").isoformat() if hasattr(persisted.get("last_event_at"), "isoformat") else persisted.get("last_event_at"),
            "lease_owner_present": bool(persisted.get("lease_owner")),
            "lease_expires_at": lease_expires_at.isoformat() if hasattr(lease_expires_at, "isoformat") else lease_expires_at,
            "control_plane_stale": lease_expired,
        })
        if lease_expired and local["status"] in {"live", "connecting", "backlog", "retrying"}:
            local["status"] = "stale"
        return local

    def _record_parser_outcome(self, total_lines: int, accepted_lines: int, rejected_lines: int) -> None:
        self._parser_accepted_lines += accepted_lines
        self._parser_rejected_lines += rejected_lines
        self._parser_last_rejection_ratio = rejected_lines / total_lines if total_lines else 0.0
        if total_lines and rejected_lines == total_lines:
            self._parser_consecutive_reject_batches += 1
        elif accepted_lines:
            self._parser_consecutive_reject_batches = 0
        metrics.increment("collector.parser_batches")
        metrics.increment("collector.parser_rejected_lines", rejected_lines)
        metrics.increment("collector.parser_accepted_lines", accepted_lines)
        metrics.gauge("collector.parser_rejection_ratio", self._parser_last_rejection_ratio)
        metrics.gauge("collector.parser_consecutive_reject_batches", self._parser_consecutive_reject_batches)

    @staticmethod
    def _task_status(task: asyncio.Task | None) -> str:
        if task is None:
            return "not_started"
        if not task.done():
            return "running"
        if task.cancelled():
            return "cancelled"
        return "failed" if task.exception() is not None else "stopped"

    def schedule_enrichment(self, ip: str) -> bool:
        """Queue one IP on the existing bounded, deduplicated worker queue."""
        if not self._governor.allow_enrichment():
            self._enrichment_deferred.add(ip)
            return False
        if ip in self._enrichment_pending:
            return False
        try:
            self._enrichment_queue.put_nowait(ip)
        except asyncio.QueueFull:
            self._enrichment_deferred.add(ip)
            return False
        self._enrichment_pending.add(ip)
        return True

    async def _publish_status(self) -> None:
        try:
            await asyncio.to_thread(self._persist_status)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"[:240]
            metrics.increment("collector.postgres_control_plane_failures")
        await bus.publish("collector_status", self.status())

    def _persist_status(self) -> None:
        CheckpointRepository().status(self.config.source_id, self.config.log_key, self.state, self.last_error)

    def _load_offset(self) -> int:
        self.last_offset = CheckpointRepository().load_offset(self.config.source_id, self.config.log_key)
        return self.last_offset

    def _acquire_lease(self) -> bool:
        return CheckpointRepository().acquire(self.config.source_id, self.config.log_key, self._owner, self.state)

    def _renew_lease(self) -> bool:
        return CheckpointRepository().renew(self.config.source_id, self._owner)

    async def _signal_lease_loss(self, error: str) -> None:
        self.last_error = error[:240]
        self.state = "standby"
        self._lease_lost.set()
        metrics.increment("collector.lease_loss")
        websocket = self._active_websocket
        if websocket is not None:
            await websocket.close()

    async def _lease_loop(self) -> None:
        while not self._stop.is_set():
            await asyncio.sleep(10)
            try:
                renewed = await asyncio.to_thread(self._renew_lease)
                if not renewed:
                    await self._signal_lease_loss("collector lease ownership lost")
                    return
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                await self._signal_lease_loss(
                    f"collector lease renewal failed: {type(exc).__name__}: {exc}"
                )
                return

    def _discard_uncommitted_storage(self) -> None:
        while True:
            try:
                self._storage_queue.get_nowait()
            except asyncio.QueueEmpty:
                break
            else:
                self._storage_queue.task_done()
        self._storage_oldest_started = None
        self._pending = []
        self.pending_lines = 0

    async def _reset_after_lease_loss(self) -> None:
        self._discard_uncommitted_storage()
        durable_offset = await asyncio.to_thread(self._load_offset)
        self._stream_offset = durable_offset
        self.last_offset = durable_offset

    async def _supervise_run(self) -> None:
        """Keep an unexpected control-plane failure from killing ingestion permanently."""
        while not self._stop.is_set():
            try:
                await self.run()
                self._supervisor_backoff = 1.0
                return
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.last_error = f"{type(exc).__name__}: {exc}"[:240]
                self.state = "retrying"
                metrics.increment("collector.task_failures")
                metrics.increment("collector.supervisor_restarts")
                logger.exception("collector run task failed; retrying")
                delay = self._supervisor_backoff
                self._supervisor_backoff = min(self._supervisor_backoff * 2, 30.0)
                try:
                    await self._publish_status()
                    await asyncio.sleep(delay)
                except asyncio.CancelledError:
                    raise

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
            self._pending = []
            self.pending_lines = 0
            self._stream_offset = end_offset
            await self._enqueue_storage(pending, end_offset, current_offset, received_at)
            return end_offset

    async def _enqueue_storage(
        self, batch: list[str], end_offset: int, current_offset: int, received_at: str,
    ) -> None:
        if not self._storage_task or self._storage_task.done():
            self._ensure_storage_worker()
        if not self._storage_task:
            new_offset, cursor, affected, new_ips = await asyncio.to_thread(
                self._commit_batch, batch, end_offset, current_offset, received_at
            )
            self._stream_offset = new_offset
            self.last_offset = new_offset
            await self._after_commit(cursor, affected, new_ips)
            return
        if self._storage_oldest_started is None:
            self._storage_oldest_started = time.monotonic()
        await self._storage_queue.put((batch, end_offset, current_offset, received_at))

    def _ensure_storage_worker(self) -> None:
        if self._storage_task and not self._storage_task.done():
            return
        self._storage_task = asyncio.create_task(self._storage_loop(), name="websocket-storage")

    async def _storage_loop(self) -> None:
        while True:
            try:
                item = await asyncio.wait_for(
                    self._storage_queue.get(), timeout=1.0
                )
            except asyncio.TimeoutError:
                continue
            if item is _STORAGE_STOP:
                self._storage_queue.task_done()
                return
            batch, end_offset, current_offset, received_at = item
            try:
                while True:
                    try:
                        new_offset, cursor, affected, new_ips = await asyncio.to_thread(
                            self._commit_batch, batch, end_offset, current_offset, received_at
                        )
                        self._stream_offset = new_offset
                        self.last_offset = new_offset
                        await self._after_commit(cursor, affected, new_ips)
                        break
                    except asyncio.CancelledError:
                        raise
                    except CheckpointCommitRejected as exc:
                        await self._signal_lease_loss(str(exc))
                        metrics.increment("collector.checkpoint_commit_rejected")
                        return
                    except Exception as exc:
                        self.last_error = f"{type(exc).__name__}: {exc}"[:240]
                        metrics.increment("collector.storage_failures")
                        await asyncio.sleep(1)
            finally:
                self._storage_queue.task_done()
                if self._storage_queue.empty():
                    self._storage_oldest_started = None

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
                    self._active_websocket = websocket
                    self.state = "backlog"
                    self.reconnect_attempt = 0
                    self.last_error = None
                    await self._publish_status()
                    async for raw in websocket:
                        if self._stop.is_set() or self._lease_lost.is_set():
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
                self._active_websocket = None
            if self._lease_lost.is_set() and not self._stop.is_set():
                self._lease_lost.clear()
                await self._reset_after_lease_loss()
                self.state = "standby"

    async def handle_message(self, raw: str | None, current_offset: int) -> int | None:
        if raw is None:
            return None
        try:
            message = json.loads(raw)
        except (TypeError, json.JSONDecodeError):
            if isinstance(raw, str):
                await self._raw_archive.append_batch([raw])
                metrics.increment("collector.malformed_frames")
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
                    valid_items = [item for item in items if isinstance(item, str)]
                    await self._raw_archive.append_batch(valid_items, received_at=datetime.fromisoformat(received_at))
                    self._pending.extend((item, received_at) for item in valid_items)
                    for line in valid_items:
                        started = metrics.timed("early_detection.processing_ms")
                        detections = self._window_detector.observe(line)
                        started()
                        for detection in detections:
                            if detection.shadow_only:
                                metrics.increment("pentest_detection.matches")
                                metrics.increment(f"pentest_detection.{detection.marker}")
                                continue
                            metrics.increment("early_detection.matches")
                            early_alerts.enqueue(detection, detection.ip)
                    self.pending_lines = len(self._pending)
                    while len(self._pending) >= self.config.batch_size:
                        batch_entries = self._pending[: self.config.batch_size]
                        self._pending = self._pending[self.config.batch_size :]
                        batch = [line for line, _received_at in batch_entries]
                        batch_received_at = min(stamp for _line, stamp in batch_entries)
                        end_offset = current_offset + sum(
                            len(line.encode("utf-8")) + 1 for line in batch
                        )
                        self._stream_offset = end_offset
                        await self._enqueue_storage(batch, end_offset, current_offset, batch_received_at)
                        current_offset = end_offset
                        flushed_offset = None
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
            self._pending = []
            self.pending_lines = 0
            self._stream_offset = end_offset
            await self._enqueue_storage(pending, end_offset, current_offset, received_at)
        if self._storage_task:
            await self._storage_queue.join()
        return self.last_offset

    async def _after_commit(
        self, cursor: int, affected: set[str], new_ips: list[str]
    ) -> None:
        for ip in new_ips:
            self.schedule_enrichment(ip)
        if affected and self.state == "live":
            await bus.publish(
                "ip_changes", {
                    "cursor": int(cursor), "count": len(affected),
                    "ips": sorted(affected), "published_at": utc_now(),
                }
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
        parse_failures: list[dict[str, Any]] = []
        for line, length in zip(lines, lengths):
            event, error_code, error_message = parse_apache_combined_diagnostic(line)
            position += length
            if not event:
                parse_failures.append({
                    "source_id": self.config.source_id,
                    "source_offset": position - length,
                    "raw_sha256": hashlib.sha256(line.encode("utf-8")).hexdigest(),
                    "parser_error_code": error_code or "PARSER_REJECTED",
                    "parser_error_message": error_message or "parser rejected line",
                    "parser_version": PARSER_VERSION,
                    "observed_at": now,
                })
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
        if parse_failures:
            self._raw_archive.write_parse_failures(parse_failures)
        self._record_parser_outcome(len(lines), len(events), len(parse_failures))
        if not events:
            self.failpoint.hit("before_checkpoint")
            from ..db.repositories import CheckpointRepository
            with postgres_store.transaction() as conn:
                CheckpointRepository().commit_offset(
                    conn, self.config.source_id, self.config.log_key,
                    int(end_offset), self.state, now, self._owner,
                )
            self.failpoint.hit("after_checkpoint")
            return end_offset, 0, set(), []
        self.failpoint.hit("after_parse")
        self._clickhouse_writer.insert_events(events)
        self.failpoint.hit("after_clickhouse_insert")
        from ..db.repositories import PgDetectionRepository
        batch_id = hashlib.sha256(f"{self.config.source_id}:{start_offset}:{end_offset}".encode()).hexdigest()
        result = PgDetectionRepository().process_events(
            events, batch_id, settings.DATASET_LIVE_ID, self.config.source_id,
            start_offset, end_offset, self.config.log_key, self.state,
            now=datetime.fromisoformat(now), failpoint=self.failpoint,
            owner=self._owner,
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
            data, error = asyncio.run(ensure_profile_postgres(ip, change_reason="enrichment"))
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
            for ip, ok, error in results:
                if not ok and error:
                    logger.error("IP enrichment failed for %s: %s", ip, error)
            successful = [ip for ip, ok, _error in results if ok]
            if successful:
                with postgres_store.transaction() as pg_conn:
                    cursor = int(pg_conn.execute("SELECT COALESCE(MAX(seq),0) AS seq FROM ip_change_log").fetchone()["seq"] or 0)
                await bus.publish("ip_changes", {
                    "cursor": cursor, "count": len(successful),
                    "ips": sorted(successful), "published_at": utc_now(),
                })

    async def privacy_loop(self) -> None:
        interval = _env_int("LOG_WS_PRIVACY_REFRESH_INTERVAL_SECONDS", 3600, 60)
        while not self._stop.is_set():
            await asyncio.sleep(interval)
            try:
                result = await refresh_due_profiles(
                    None, limit=_env_int("PRIVACY_REFRESH_BATCH", 100, 1)
                )
                changed_ips = result.get("processed_ips", [])
                if changed_ips:
                    with postgres_store.transaction() as conn:
                        cursor = int(conn.execute("SELECT COALESCE(MAX(seq),0) AS seq FROM ip_change_log").fetchone()["seq"] or 0)
                    await bus.publish(
                        "ip_changes", {"cursor": cursor, "count": len(changed_ips), "ips": changed_ips, "published_at": utc_now()}
                    )
                self._privacy_failures = 0
                self._privacy_last_error = None
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self._privacy_failures += 1
                self._privacy_last_error = f"{type(exc).__name__}: {exc}"
                metrics.increment("collector.privacy_refresh_failures")
                logger.warning("Privacy refresh failed (%s consecutive): %s", self._privacy_failures, exc)

    async def _publish_rare_changes(self, changed_ips: list[str]) -> None:
        with postgres_store.transaction() as conn:
            cursor = int(conn.execute("SELECT COALESCE(MAX(seq),0) AS seq FROM ip_change_log").fetchone()["seq"] or 0)
        await bus.publish(
            "ip_changes", {"cursor": cursor, "count": len(changed_ips), "ips": changed_ips, "published_at": utc_now()}
        )


collector = WebSocketCollector()
