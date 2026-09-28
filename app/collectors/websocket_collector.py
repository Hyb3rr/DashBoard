from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import os
import time
from typing import Any

from .config import CollectorConfig
from . import background
from . import batching
from . import session
from ..db import clickhouse as clickhouse_store
from ..core import metrics
from ..services.realtime_bus import RealtimeBus
from ..db.repositories import CheckpointRepository
from ..core.fast_detection import ShortWindowDetector
from ..services.rare_path_detector import periodic_shadow
from ..services.early_alerts import early_alerts
from ..services.workload_governor import WorkloadGovernor
from ..services.ai_runtime import ai_runtime
from ..services.raw_log_archive import RawLogArchive
from ..core.failpoints import NoopFailpoint
from .storage import BatchCommitter, StorageWorker
from .runtime_state import CollectorTasks, ParserStats, StorageState

def utc_now() -> str:
    """Return the current UTC time as an ISO string."""
    return datetime.now(timezone.utc).isoformat()




bus = RealtimeBus()


def _env_int(name: str, default: int, minimum: int) -> int:
    """Read an integer environment value and enforce its minimum."""
    try:
        return max(minimum, int(os.getenv(name, str(default))))
    except (TypeError, ValueError):
        return default


class WebSocketCollector:
    """Coordinate collector lifecycle and connect the ingest components."""

    def __init__(self, config: CollectorConfig | None = None) -> None:
        """Initialize configuration, state, queues, and supporting workers."""
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
        self.stop_event = asyncio.Event()
        self.tasks = CollectorTasks()
        self.storage = StorageState()
        self.storage_worker = StorageWorker(self)
        self.parser_stats = ParserStats()
        self._window_detector = ShortWindowDetector()
        self._governor = WorkloadGovernor()
        self.session = session.CollectorSession(self)
        self.enrichment = background.EnrichmentWorker(
            self.stop_event, self._governor, bus, utc_now, _env_int
        )
        self.privacy_refresh = background.PrivacyRefreshWorker(
            self.stop_event, bus, utc_now, _env_int
        )
        self.failpoint = NoopFailpoint()
        self._raw_archive = RawLogArchive(self.config.source_id)
        self._clickhouse_writer = clickhouse_store.ClickHouseWriter()
        self._batch_committer = BatchCommitter(
            self.config,
            self.parser_stats.record,
        )

    async def start(self) -> None:
        """Start the archive, background workers, and enabled ingest tasks."""
        if os.getenv("RARE_PATH_ENABLED", "true").strip().lower() in {"1", "true", "yes", "on"}:
            self.tasks.rare_path = asyncio.create_task(
                periodic_shadow(
                    self.stop_event,
                    on_changed=lambda changed: background.publish_rare_changes(
                        changed, bus, utc_now
                    ),
                    should_run=self._governor.allow_rare_path,
                ),
                name="rare-path-shadow",
            )
        if self.tasks.run and not self.tasks.run.done():
            await self._publish_status()
            return
        if self.tasks.run and self.tasks.run.done():
            try:
                self.tasks.run.exception()
            except asyncio.CancelledError:
                pass
            self.tasks.run = None
        self.stop_event.clear()
        await self._raw_archive.start()

        # Enrichment is also requested by the IP detail API. It must remain
        # available when websocket ingestion is disabled (the default for a
        # local/demo deployment), otherwise those requests accumulate forever
        # in the queue with no worker to process them.
        self.tasks.enrichment = asyncio.create_task(
            self.enrichment.run(),
            name="websocket-enrichment",
        )
        self.tasks.governor = asyncio.create_task(
            background.governor_loop(self, early_alerts), name="workload-governor"
        )
        self.tasks.privacy = asyncio.create_task(
            self.privacy_refresh.run(),
            name="websocket-privacy-refresh",
        )
        await early_alerts.start()
        if self.config.enabled and self.config.valid:
            self.tasks.run = asyncio.create_task(
                self.session.supervise(utc_now), name="websocket-collector"
            )
            self.tasks.flush = asyncio.create_task(
                batching.flush_loop(self), name="websocket-flush"
            )
            self.storage_worker.start()
        else:
            self.state = "disabled" if not self.config.enabled else "config_error"
        await self._publish_status()

    async def stop(self) -> None:
        """Stop producers, drain the storage queue, and close runtime resources."""
        self.stop_event.set()
        producer_tasks = [
            task
            for task in (
                self.tasks.run,
                self.tasks.flush,
                self.tasks.enrichment,
                self.tasks.governor,
                self.tasks.privacy,
                self.tasks.rare_path,
            )
            if task
        ]
        for task in producer_tasks:
            task.cancel()
        if producer_tasks:
            await asyncio.gather(*producer_tasks, return_exceptions=True)
        if self.storage.pending:
            await batching.flush_pending(self)
        await self.storage_worker.drain_and_stop()
        await self._raw_archive.stop()
        self._clickhouse_writer.close()
        self.tasks = CollectorTasks()
        await early_alerts.stop()
        self.state = "stopped"
        await self._publish_status()

    def status(self) -> dict[str, Any]:
        """Build a snapshot of collector runtime state and metrics."""
        metrics.gauge("collector.pending_lines", self.pending_lines)
        metrics.gauge("enrichment.queue_depth", self.enrichment.queue.qsize())
        oldest_age_ms = 0.0
        if self.storage_worker.oldest_started is not None:
            oldest_age_ms = (
                time.monotonic() - self.storage_worker.oldest_started
            ) * 1000
        state = self._governor.state()
        metrics.gauge("storage.queue_depth", self.storage_worker.queue.qsize())
        metrics.gauge("storage.oldest_age_ms", oldest_age_ms)
        metrics.gauge("collector.reconnect_attempt", self.reconnect_attempt)
        raw_archive = self._raw_archive.status()
        tasks = {
            "run": self._task_status(self.tasks.run),
            "flush": self._task_status(self.tasks.flush),
            "storage": self._task_status(self.storage_worker.task),
            "enrichment": self._task_status(self.tasks.enrichment),
            "privacy": self._task_status(self.tasks.privacy),
            "raw_writer": raw_archive.get("writer_status", "unknown"),
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
            "parser": self.parser_stats.snapshot(),
            "privacy_refresh": {
                "status": "failed" if self.privacy_refresh.consecutive_failures else "ok",
                "consecutive_failures": self.privacy_refresh.consecutive_failures,
                "last_error": self.privacy_refresh.last_error,
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

    @staticmethod
    def _task_status(task: asyncio.Task | None) -> str:
        """Convert an asyncio task state into a health-report string."""
        if task is None:
            return "not_started"
        if not task.done():
            return "running"
        if task.cancelled():
            return "cancelled"
        return "failed" if task.exception() is not None else "stopped"

    async def _publish_status(self) -> None:
        """Persist collector status off-loop, then publish the update."""
        try:
            await asyncio.to_thread(self._persist_status)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"[:240]
            metrics.increment("collector.postgres_control_plane_failures")
        await bus.publish("collector_status", self.status())

    def _persist_status(self) -> None:
        """Write the current status and error to the PostgreSQL control plane."""
        CheckpointRepository().status(self.config.source_id, self.config.log_key, self.state, self.last_error)

    async def _after_commit(
        self, cursor: int, affected: set[str], new_ips: list[str]
    ) -> None:
        """Queue enrichment for new IPs and publish the committed cursor."""
        for ip in new_ips:
            self.enrichment.schedule(ip)
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
        """Preserve the existing commit API while delegating batch writes."""
        return self._batch_committer.commit(
            lines,
            end_offset,
            current_offset,
            received_at,
            utc_now(),
            state=self.state,
            owner=self.session.owner,
            failpoint=self.failpoint,
            raw_archive=self._raw_archive,
            clickhouse_writer=self._clickhouse_writer,
        )

collector = WebSocketCollector()
