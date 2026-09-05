"""Bounded, non-blocking delivery path for preliminary security alerts."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

from ..core import metrics
from ..core.fast_detection import EarlyDetection
from .telegram import format_early_alert, send_message


class EarlyAlertPublisher:
    def __init__(self, maxsize: int = 1000, publish: Callable[[str, dict[str, Any]], Awaitable[None]] | None = None) -> None:
        self._queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=maxsize)
        self._publish = publish
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()

    async def start(self) -> None:
        if self._task:
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._run(), name="early-alerts")

    async def stop(self) -> None:
        self._stop.set()
        if self._task:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
        self._task = None

    def enqueue(self, detection: EarlyDetection, ip: str | None = None) -> bool:
        payload = {
            "type": "preliminary",
            "ip": ip,
            "rule_id": detection.rule_id,
            "severity": "high",
            "request": f"{detection.method} {detection.path}",
        }
        try:
            self._queue.put_nowait(payload)
        except asyncio.QueueFull:
            metrics.increment("early_alert.queue_overflow")
            return False
        metrics.increment("early_alert.enqueued")
        return True

    async def _run(self) -> None:
        while not self._stop.is_set():
            try:
                payload = await asyncio.wait_for(self._queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            try:
                publish = self._publish
                if publish is None:
                    from ..collectors.websocket_collector import bus
                    publish = bus.publish
                await publish("early_alert", payload)
                metrics.increment("early_alert.delivered")
                await send_message(format_early_alert(payload))
            finally:
                self._queue.task_done()

    def status(self) -> dict[str, int]:
        depth = self._queue.qsize()
        metrics.gauge("early_alert.queue_depth", depth)
        return {"queue_depth": depth}


early_alerts = EarlyAlertPublisher()
