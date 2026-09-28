"""WebSocket connection and reconnect session for the collector runtime."""

from __future__ import annotations

import asyncio
import inspect
import logging
import os
import socket
from typing import Any
from urllib.parse import urlencode

from ..core import metrics
from ..db.repositories import CheckpointRepository
from . import batching

logger = logging.getLogger(__name__)


def connection_url(collector: Any, offset: int) -> str:
    """Build the upstream URL with the log key, source ID, and offset."""
    separator = "&" if "?" in collector.config.url else "?"
    query = urlencode(
        {
            "log": collector.config.log_key,
            "offset": int(offset),
            "client": collector.config.source_id,
            "clientId": collector.config.source_id,
            "source_id": collector.config.source_id,
        }
    )
    return collector.config.url + separator + query


def connection_headers(collector: Any) -> dict[str, str]:
    """Build the bearer authorization header for the upstream WebSocket."""
    return {"Authorization": f"Bearer {collector.config.token}"}


class CollectorSession:
    """Own upstream connection, lease, replay offset and reconnect state."""

    def __init__(self, collector: Any) -> None:
        """Bind session state to the collector's durable control-plane callbacks."""
        self.collector = collector
        self.owner = f"{socket.gethostname()}:{os.getpid()}"
        self.lease_lost = asyncio.Event()
        self.active_websocket = None
        self.backoff = 1.0
        self.supervisor_backoff = 1.0

    async def supervise(self, now) -> None:
        """Restart the session after transient control-plane or socket failures."""
        collector = self.collector
        while not collector.stop_event.is_set():
            try:
                await self.run(now)
                self.supervisor_backoff = 1.0
                return
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                collector.last_error = f"{type(exc).__name__}: {exc}"[:240]
                collector.state = "retrying"
                metrics.increment("collector.task_failures")
                metrics.increment("collector.supervisor_restarts")
                logger.exception("collector run task failed; retrying")
                delay = self.supervisor_backoff
                self.supervisor_backoff = min(self.supervisor_backoff * 2, 30.0)
                try:
                    await collector._publish_status()
                    await asyncio.sleep(delay)
                except asyncio.CancelledError:
                    raise

    async def run(self, now) -> None:
        """Manage lease acquisition, WebSocket reconnects and incoming frames."""
        collector = self.collector
        if not collector.config.valid:
            collector.state = "config_error"
            await collector._publish_status()
            return
        try:
            import websockets
        except ImportError:
            collector.state = "config_error"
            collector.last_error = "websockets dependency is not installed"
            await collector._publish_status()
            return

        await asyncio.to_thread(self.load_offset)
        while not collector.stop_event.is_set():
            if not await asyncio.to_thread(self.acquire_lease):
                collector.state = "standby"
                await collector._publish_status()
                await asyncio.sleep(10)
                continue
            await self._run_lease_cycle(websockets, now)

    async def _run_lease_cycle(self, websockets, now) -> None:
        """Run one leased socket cycle and recover cleanly from ownership loss."""
        collector = self.collector
        lease_task = asyncio.create_task(self.lease_loop(), name="websocket-lease")
        try:
            await self._connect_and_receive(websockets, now)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            collector.last_error = f"{type(exc).__name__}: {exc}"[:240]
            collector.reconnect_attempt += 1
            metrics.increment("collector.reconnects")
            collector.state = "retrying"
            await collector._publish_status()
            await asyncio.sleep(self.backoff)
            self.backoff = min(self.backoff * 2, 30.0)
        finally:
            lease_task.cancel()
            await asyncio.gather(lease_task, return_exceptions=True)
            self.active_websocket = None
        if self.lease_lost.is_set() and not collector.stop_event.is_set():
            self.lease_lost.clear()
            await self.reset_after_lease_loss()
            collector.state = "standby"

    async def _connect_and_receive(self, websockets, now) -> None:
        """Connect from the durable offset and consume upstream frames in order."""
        collector = self.collector
        collector.state = "connecting"
        await collector._publish_status()
        offset = await asyncio.to_thread(self.load_offset)
        url = connection_url(collector, offset)
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
        connect_options[header_argument] = connection_headers(collector)
        async with websockets.connect(url, **connect_options) as websocket:
            self.active_websocket = websocket
            collector.state = "backlog"
            collector.reconnect_attempt = 0
            collector.last_error = None
            await collector._publish_status()
            async for raw in websocket:
                if collector.stop_event.is_set() or self.lease_lost.is_set():
                    break
                result = await batching.handle_message(collector, raw, offset, now)
                if result is not None:
                    offset = result
                    collector.last_offset = offset
        self.backoff = 1.0

    def load_offset(self) -> int:
        """Load the last durably committed source offset."""
        collector = self.collector
        offset = CheckpointRepository().load_offset(
            collector.config.source_id, collector.config.log_key
        )
        collector.last_offset = offset
        return offset

    def acquire_lease(self) -> bool:
        """Acquire exclusive ownership before opening the upstream stream."""
        collector = self.collector
        return CheckpointRepository().acquire(
            collector.config.source_id,
            collector.config.log_key,
            self.owner,
            collector.state,
        )

    def renew_lease(self) -> bool:
        """Renew the active source lease."""
        collector = self.collector
        return CheckpointRepository().renew(collector.config.source_id, self.owner)

    async def signal_lease_loss(self, error: str) -> None:
        """Close the active socket and notify the session that ownership ended."""
        collector = self.collector
        collector.last_error = error[:240]
        collector.state = "standby"
        self.lease_lost.set()
        metrics.increment("collector.lease_loss")
        if self.active_websocket is not None:
            await self.active_websocket.close()

    async def lease_loop(self) -> None:
        """Renew the source lease periodically and fail closed on errors."""
        collector = self.collector
        while not collector.stop_event.is_set():
            await asyncio.sleep(10)
            try:
                if not await asyncio.to_thread(self.renew_lease):
                    await self.signal_lease_loss("collector lease ownership lost")
                    return
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                await self.signal_lease_loss(
                    f"collector lease renewal failed: {type(exc).__name__}: {exc}"
                )
                return

    async def reset_after_lease_loss(self) -> None:
        """Discard volatile batches and restore the durable replay offset."""
        collector = self.collector
        collector.storage_worker.discard_uncommitted()
        collector.storage.pending.clear()
        collector.pending_lines = 0
        offset = await asyncio.to_thread(self.load_offset)
        collector.storage.stream_offset = offset
        collector.last_offset = offset
