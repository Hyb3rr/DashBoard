"""Pressure state for preserving ingest and alerting under load."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class WorkloadState:
    mode: str
    storage_queue_depth: int
    storage_oldest_age_ms: float
    early_alert_queue_depth: int


class WorkloadGovernor:
    def __init__(self, pressure_depth: int = 500, critical_depth: int = 900,
                 pressure_age_ms: float = 10_000, critical_age_ms: float = 60_000) -> None:
        """Configure queue-depth and queue-age thresholds for workload modes."""
        self.pressure_depth = pressure_depth
        self.critical_depth = critical_depth
        self.pressure_age_ms = pressure_age_ms
        self.critical_age_ms = critical_age_ms
        self._state = WorkloadState("NORMAL", 0, 0.0, 0)

    def update(self, storage_queue_depth: int, storage_oldest_age_ms: float = 0.0,
               early_alert_queue_depth: int = 0) -> WorkloadState:
        """Update pressure mode from current storage and alert queue measurements."""
        if storage_queue_depth >= self.critical_depth or storage_oldest_age_ms >= self.critical_age_ms:
            mode = "CRITICAL"
        elif storage_queue_depth >= self.pressure_depth or storage_oldest_age_ms >= self.pressure_age_ms:
            mode = "PRESSURE"
        else:
            mode = "NORMAL"
        self._state = WorkloadState(mode, storage_queue_depth, storage_oldest_age_ms, early_alert_queue_depth)
        return self._state

    def state(self) -> WorkloadState:
        """Return the latest workload state without recalculating pressure."""
        return self._state

    def allow_rare_path(self) -> bool:
        """Allow expensive rare-path work only when the system is normal."""
        return self._state.mode == "NORMAL"

    def allow_enrichment(self) -> bool:
        """Allow background enrichment unless storage pressure is critical."""
        return self._state.mode != "CRITICAL"
