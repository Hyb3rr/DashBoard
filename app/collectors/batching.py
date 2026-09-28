"""Batch intake, flush scheduling and source-offset bookkeeping."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime
from typing import Any, Callable

from ..core import metrics
from ..services.early_alerts import early_alerts


async def flush_loop(collector: Any) -> None:
    """Run the timer that flushes partial batches."""
    interval = collector.config.flush_ms / 1000
    while not collector.stop_event.is_set():
        await asyncio.sleep(interval)
        await flush_pending(collector)


async def flush_pending(collector: Any) -> int | None:
    """Turn buffered lines into a batch and calculate its next offset."""
    async with collector.storage.flush_lock:
        if not collector.storage.pending:
            return None
        pending_entries = collector.storage.pending
        pending = [line for line, _received_at in pending_entries]
        received_at = min(stamp for _line, stamp in pending_entries)
        current_offset = max(collector.last_offset, collector.storage.stream_offset)
        end_offset = current_offset + sum(
            len(line.encode("utf-8")) + 1 for line in pending
        )
        collector.storage.pending = []
        collector.pending_lines = 0
        collector.storage.stream_offset = end_offset
        await enqueue_storage(
            collector,
            pending, end_offset, current_offset, received_at
        )
        return end_offset


async def enqueue_storage(
    collector: Any,
    batch: list[str],
    end_offset: int,
    current_offset: int,
    received_at: str,
) -> None:
    """Submit a batch to the collector's ordered storage worker."""
    await collector.storage_worker.enqueue(
        batch, end_offset, current_offset, received_at
    )


async def handle_message(
    collector: Any,
    raw: str | None,
    current_offset: int,
    now: Callable[[], str],
) -> int | None:
    """Archive and route a lines or offset frame into the processing buffer."""
    if raw is None:
        return None
    message = _parse_message(raw)
    if message is None:
        return None
    kind = message.get("type")
    if kind == "_malformed":
        await _archive_malformed(collector, message["raw"])
        return None
    if kind == "lines":
        return await _handle_lines(collector, message.get("items"), current_offset, now)
    if kind == "backlog_done":
        await _mark_backlog_complete(collector)
        return None
    if kind == "offset":
        return await _handle_offset(collector, message, current_offset, now)
    return None


def _parse_message(raw: str) -> dict | None:
    """Decode a collector frame or mark malformed input for archival."""
    try:
        message = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        if isinstance(raw, str):
            return {"type": "_malformed", "raw": raw}
    return message if isinstance(message, dict) else None


async def _archive_malformed(collector, raw: str) -> None:
    """Persist malformed frame evidence and increment its diagnostic counter."""
    await collector._raw_archive.append_batch([raw])
    metrics.increment("collector.malformed_frames")


async def _handle_lines(collector, items, current_offset, now):
    """Archive valid line frames, detect early signals, and enqueue full batches."""
    if not isinstance(items, list):
        return None
    async with collector.storage.flush_lock:
        current_offset = max(current_offset, collector.storage.stream_offset)
        collector.storage.stream_offset = current_offset
        received_at = now()
        valid_items = [item for item in items if isinstance(item, str)]
        await collector._raw_archive.append_batch(
            valid_items,
            received_at=datetime.fromisoformat(received_at),
        )
        collector.storage.pending.extend((item, received_at) for item in valid_items)
        _observe_early_detections(collector, valid_items)
        collector.pending_lines = len(collector.storage.pending)
        while len(collector.storage.pending) >= collector.config.batch_size:
            batch_entries = collector.storage.pending[:collector.config.batch_size]
            collector.storage.pending = collector.storage.pending[collector.config.batch_size:]
            batch = [line for line, _received_at in batch_entries]
            batch_received_at = min(stamp for _line, stamp in batch_entries)
            end_offset = current_offset + sum(len(line.encode("utf-8")) + 1 for line in batch)
            collector.storage.stream_offset = end_offset
            await enqueue_storage(collector, batch, end_offset, current_offset, batch_received_at)
            current_offset = end_offset
        collector.pending_lines = len(collector.storage.pending)
    return None


def _observe_early_detections(collector, lines) -> None:
    """Run bounded early detection and publish its resulting alert signals."""
    for line in lines:
        finish_timing = metrics.timed("early_detection.processing_ms")
        detections = collector._window_detector.observe(line)
        finish_timing()
        for detection in detections:
            if detection.shadow_only:
                metrics.increment("pentest_detection.matches")
                metrics.increment(f"pentest_detection.{detection.marker}")
                continue
            metrics.increment("early_detection.matches")
            early_alerts.enqueue(detection, detection.ip)


async def _mark_backlog_complete(collector) -> None:
    """Switch collector status to live after upstream backlog replay ends."""
    collector.state = "live"
    await collector._publish_status()


async def _handle_offset(collector, message, current_offset, now):
    """Flush pending lines through an upstream offset and await durable commit."""
    try:
        end_offset = int(message["value"])
    except (KeyError, TypeError, ValueError):
        return None
    current_offset = max(current_offset, collector.storage.stream_offset)
    if end_offset < current_offset:
        return None
    async with collector.storage.flush_lock:
        pending_entries = collector.storage.pending
        pending = [line for line, _received_at in pending_entries]
        received_at = min(
            (stamp for _line, stamp in pending_entries), default=now()
        )
        collector.storage.pending = []
        collector.pending_lines = 0
        collector.storage.stream_offset = end_offset
        await enqueue_storage(
            collector,
            pending, end_offset, current_offset, received_at
        )
    if collector.storage_worker.task:
        await collector.storage_worker.queue.join()
    return collector.last_offset
