"""Process-local SSE fan-out bus for durable realtime wake-ups."""

from __future__ import annotations

import asyncio
from typing import Any

from ..core import metrics


class RealtimeBus:
    """Fan out notifications; durable change rows remain the source of truth."""

    def __init__(self) -> None:
        """Create the process-local subscriber registry and synchronization lock."""
        self._subscriptions: set[_RealtimeSubscription] = set()
        self._lock = asyncio.Lock()

    async def publish(self, event: str, payload: dict[str, Any]) -> None:
        """Fan out an event while coalescing pending durable cursor wake-ups."""
        async with self._lock:
            for subscription in tuple(self._subscriptions):
                if event == "ip_changes" and subscription.ip_changes_pending:
                    subscription.latest_ip_changes = payload
                    continue
                try:
                    subscription.queue.put_nowait((event, payload))
                except asyncio.QueueFull:
                    metrics.increment("realtime_bus_dropped_events")
                    continue
                if event == "ip_changes":
                    subscription.ip_changes_pending = True

    async def open_subscription(self) -> "_RealtimeSubscription":
        """Register and return a queue-backed realtime subscription."""
        subscription = _RealtimeSubscription(self)
        async with self._lock:
            self._subscriptions.add(subscription)
        return subscription

    async def subscribe(self):
        """Yield bus events and acknowledge each one after consumer delivery."""
        subscription = await self.open_subscription()
        try:
            while True:
                event, payload = await subscription.get()
                yield event, payload
                await subscription.ack(event)
        finally:
            await subscription.close()


class _RealtimeSubscription:
    def __init__(self, bus: RealtimeBus) -> None:
        """Initialize a bounded queue and coalesced IP-change state."""
        self.bus = bus
        self.queue: asyncio.Queue[tuple[str, dict[str, Any]]] = asyncio.Queue(maxsize=100)
        self.ip_changes_pending = False
        self.latest_ip_changes: dict[str, Any] | None = None

    async def get(self) -> tuple[str, dict[str, Any]]:
        """Wait for and return the next queued event."""
        return await self.queue.get()

    async def ack(self, event: str) -> None:
        """Release or enqueue the latest cursor after an IP-change delivery."""
        if event != "ip_changes":
            return
        async with self.bus._lock:
            if self.latest_ip_changes is None:
                self.ip_changes_pending = False
            else:
                latest = self.latest_ip_changes
                self.latest_ip_changes = None
                self.queue.put_nowait(("ip_changes", latest))

    async def close(self) -> None:
        """Remove this subscription from the bus registry."""
        async with self.bus._lock:
            self.bus._subscriptions.discard(self)
