"""Synchronous persistence boundary for collector batches."""

from __future__ import annotations

import asyncio
import hashlib
import time
from datetime import datetime
from typing import Any, Callable

from ..config import settings
from ..core.failpoints import Failpoint
from ..core.logs import PARSER_VERSION, parse_apache_combined_diagnostic
from ..core import metrics
from ..db import postgres as postgres_store
from ..db.repositories import CheckpointRepository, PgDetectionRepository
from ..db.repositories import CheckpointCommitRejected
from .config import CollectorConfig


class _StorageStop:
    """Signal that accepted storage work has drained."""


_STORAGE_STOP = _StorageStop()


class StorageWorker:
    """Own the bounded storage queue and ordered batch commit loop."""

    def __init__(self, collector: Any, maxsize: int = 1000) -> None:
        """Bind the worker to collector commit and post-commit callbacks."""
        self.collector = collector
        self.queue: asyncio.Queue[Any] = asyncio.Queue(maxsize=maxsize)
        self.task: asyncio.Task[Any] | None = None
        self.oldest_started: float | None = None

    def start(self) -> asyncio.Task[Any]:
        """Start one ordered storage consumer unless it is already active."""
        if self.task is None or self.task.done():
            self.task = asyncio.create_task(self.run(), name="websocket-storage")
            self.collector.tasks.storage = self.task
        return self.task

    async def enqueue(
        self, batch: list[str], end_offset: int, current_offset: int,
        received_at: str,
    ) -> None:
        """Queue a batch and start the consumer if necessary."""
        task = self.start()
        if task is None:
            raise RuntimeError("storage worker failed to start")
        if self.oldest_started is None:
            self.oldest_started = time.monotonic()
        await self.queue.put((batch, end_offset, current_offset, received_at))

    async def drain_and_stop(self) -> None:
        """Drain accepted batches before stopping the consumer."""
        if self.task and not self.task.done():
            await self.queue.join()
            await self.queue.put(_STORAGE_STOP)
            await self.task
        elif self.task:
            self.discard_uncommitted()

    def discard_uncommitted(self) -> None:
        """Discard queued batches and balance queue completion accounting."""
        while True:
            try:
                self.queue.get_nowait()
            except asyncio.QueueEmpty:
                break
            else:
                self.queue.task_done()
        self.oldest_started = None

    async def run(self) -> None:
        """Commit queued batches in order and retry transient storage errors."""
        collector = self.collector
        while True:
            try:
                item = await asyncio.wait_for(self.queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            if item is _STORAGE_STOP:
                self.queue.task_done()
                return
            batch, end_offset, current_offset, received_at = item
            try:
                while True:
                    try:
                        new_offset, cursor, affected, new_ips = await asyncio.to_thread(
                            collector._commit_batch,
                            batch,
                            end_offset,
                            current_offset,
                            received_at,
                        )
                        collector.storage.stream_offset = new_offset
                        collector.last_offset = new_offset
                        await collector._after_commit(cursor, affected, new_ips)
                        break
                    except asyncio.CancelledError:
                        raise
                    except CheckpointCommitRejected as exc:
                        await collector.session.signal_lease_loss(str(exc))
                        metrics.increment("collector.checkpoint_commit_rejected")
                        return
                    except Exception as exc:
                        collector.last_error = f"{type(exc).__name__}: {exc}"[:240]
                        metrics.increment("collector.storage_failures")
                        await asyncio.sleep(1)
            finally:
                self.queue.task_done()
                if self.queue.empty():
                    self.oldest_started = None


class BatchCommitter:
    """Parse and durably persist one accepted collector batch."""

    def __init__(
        self,
        config: CollectorConfig,
        record_parser_outcome: Callable[[int, int, int], None],
    ) -> None:
        """Store collector configuration and the parser-metrics callback."""
        self.config = config
        self.record_parser_outcome = record_parser_outcome

    def _parse_lines(self, lines, start_offset, received_at, now):
        """Normalize batch lines and collect parser rejection evidence."""
        position = start_offset
        events = []
        parse_failures = []
        for line in lines:
            length = len(line.encode("utf-8")) + 1
            event, error_code, error_message = parse_apache_combined_diagnostic(line)
            if not event:
                parse_failures.append({
                    "source_id": self.config.source_id,
                    "source_offset": position,
                    "raw_sha256": hashlib.sha256(line.encode("utf-8")).hexdigest(),
                    "parser_error_code": error_code or "PARSER_REJECTED",
                    "parser_error_message": error_message or "parser rejected line",
                    "parser_version": PARSER_VERSION,
                    "observed_at": now,
                })
            else:
                source = f"ws:{self.config.source_id}"
                line_hash = hashlib.sha256(f"{source}\0{position}\0{line}".encode()).hexdigest()
                events.append({
                    **event,
                    "dataset_id": settings.DATASET_LIVE_ID,
                    "source_id": self.config.source_id,
                    "source_offset": position,
                    "event_id": line_hash,
                    "ingested_at": now,
                    "pipeline_received_at": received_at or now,
                    "raw_line": line,
                })
            position += length
        return events, parse_failures

    def _commit_empty_batch(self, end_offset, state, now, owner, failpoint):
        """Advance a checkpoint for a batch containing no valid events."""
        failpoint.hit("before_checkpoint")
        with postgres_store.transaction() as conn:
            CheckpointRepository().commit_offset(
                conn, self.config.source_id, self.config.log_key,
                int(end_offset), state, now, owner,
            )
        failpoint.hit("after_checkpoint")
        return end_offset, 0, set(), []

    def _persist_events(
        self, events, start_offset, end_offset, state, owner, now,
        failpoint, clickhouse_writer,
    ):
        """Persist normalized events through ClickHouse and PostgreSQL in order."""
        failpoint.hit("after_parse")
        clickhouse_writer.insert_events(events)
        failpoint.hit("after_clickhouse_insert")
        batch_id = hashlib.sha256(
            f"{self.config.source_id}:{start_offset}:{end_offset}".encode()
        ).hexdigest()
        result = PgDetectionRepository().process_events(
            events, batch_id, settings.DATASET_LIVE_ID, self.config.source_id,
            start_offset, end_offset, self.config.log_key, state,
            now=datetime.fromisoformat(now), failpoint=failpoint,
            owner=owner,
        )
        affected = set(result.get("affected", set()))
        with postgres_store.transaction() as conn:
            cursor = int(conn.execute(
                "SELECT COALESCE(MAX(seq),0) AS seq FROM ip_change_log"
            ).fetchone()["seq"] or 0)
            profiles = conn.execute(
                "SELECT host(ip) AS ip FROM ip_profiles WHERE ip = ANY(%s::inet[])",
                (list(affected),),
            ).fetchall() if affected else []
        profiled = {str(row["ip"]) for row in profiles}
        failpoint.hit("before_ack")
        return end_offset, cursor, affected, sorted(affected - profiled)

    def commit(
        self,
        lines: list[str],
        end_offset: int,
        current_offset: int,
        received_at: str | None,
        now: str,
        *,
        state: str,
        owner: str,
        failpoint: Failpoint,
        raw_archive: Any,
        clickhouse_writer: Any,
    ) -> tuple[int, int, set[str], list[str]]:
        """Parse and persist a batch, then return its cursor and affected IPs."""
        lengths = [len(line.encode("utf-8")) + 1 for line in lines]
        start_offset = max(current_offset, end_offset - sum(lengths))
        events, parse_failures = self._parse_lines(lines, start_offset, received_at, now)
        if parse_failures:
            raw_archive.write_parse_failures(parse_failures)
        self.record_parser_outcome(len(lines), len(events), len(parse_failures))
        if not events:
            return self._commit_empty_batch(end_offset, state, now, owner, failpoint)
        return self._persist_events(
            events, start_offset, end_offset, state, owner, now,
            failpoint, clickhouse_writer,
        )
