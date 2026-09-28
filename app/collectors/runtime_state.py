"""Typed state containers owned by collector runtime components."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from ..core import metrics


@dataclass
class CollectorTasks:
    """Hold task handles so startup and shutdown manage one task group."""

    run: asyncio.Task[Any] | None = None
    flush: asyncio.Task[Any] | None = None
    storage: asyncio.Task[Any] | None = None
    enrichment: asyncio.Task[Any] | None = None
    governor: asyncio.Task[Any] | None = None
    privacy: asyncio.Task[Any] | None = None
    rare_path: asyncio.Task[Any] | None = None


@dataclass
class StorageState:
    """Track unflushed lines and their source-offset boundary."""

    pending: list[tuple[str, str]] = field(default_factory=list)
    stream_offset: int = 0
    flush_lock: asyncio.Lock = field(default_factory=asyncio.Lock)


@dataclass
class ParserStats:
    """Track parser acceptance, rejection and consecutive bad batches."""

    accepted_lines: int = 0
    rejected_lines: int = 0
    consecutive_reject_batches: int = 0
    last_rejection_ratio: float = 0.0

    def record(self, total: int, accepted: int, rejected: int) -> None:
        """Update parser health counters and their exported metrics."""
        self.accepted_lines += accepted
        self.rejected_lines += rejected
        self.last_rejection_ratio = rejected / total if total else 0.0
        if total and rejected == total:
            self.consecutive_reject_batches += 1
        elif accepted:
            self.consecutive_reject_batches = 0
        metrics.increment("collector.parser_batches")
        metrics.increment("collector.parser_rejected_lines", rejected)
        metrics.increment("collector.parser_accepted_lines", accepted)
        metrics.gauge("collector.parser_rejection_ratio", self.last_rejection_ratio)
        metrics.gauge(
            "collector.parser_consecutive_reject_batches",
            self.consecutive_reject_batches,
        )

    def snapshot(self) -> dict[str, Any]:
        """Return the parser health fields used by collector status."""
        return {
            "accepted_lines": self.accepted_lines,
            "rejected_lines": self.rejected_lines,
            "last_rejection_ratio": self.last_rejection_ratio,
            "consecutive_reject_batches": self.consecutive_reject_batches,
            "status": "degraded" if self.consecutive_reject_batches >= 3 else "ok",
        }


@dataclass
class PrivacyRefreshState:
    """Track consecutive privacy-refresh failures and the last error."""

    consecutive_failures: int = 0
    last_error: str | None = None
