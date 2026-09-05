"""Disabled-by-default semantic change-feed consumer for AI jobs."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..db.ai_trigger import AiTriggerRepository
from .ai_trigger_policy import build_trigger_identity, is_meaningful_trigger


class AiTriggerConsumer:
    def __init__(self, repository: AiTriggerRepository, packet_loader: Callable[[str], dict[str, Any]], enabled: bool = False, batch_size: int = 50, max_pending_jobs: int = 1):
        self.repository = repository
        self.packet_loader = packet_loader
        self.enabled = bool(enabled)
        self.batch_size = max(1, min(int(batch_size), 500))
        self.max_pending_jobs = max(1, int(max_pending_jobs))

    def run_once(self) -> int:
        if not self.enabled:
            return 0
        cursor = self.repository.get_cursor()
        events, _current = self.repository.read_batch(cursor, self.batch_size)
        created = 0
        for event in events:
            self.repository.record_event(event, is_meaningful_trigger(event))
        capacity = self.repository.available_capacity(self.max_pending_jobs)
        for item in self.repository.deferred(capacity):
            packet = self.packet_loader(str(item["ip"]))
            identity = build_trigger_identity(packet)
            if self.repository.materialize(item, identity, packet):
                created += 1
        return created


__all__ = ["AiTriggerConsumer"]
