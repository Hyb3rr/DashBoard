"""Provider-neutral local reasoning boundary."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol


@dataclass(frozen=True)
class ReasoningResult:
    status: str
    evidence_fingerprint: str | None = None
    raw_response: Mapping[str, Any] | None = None
    error: str | None = None


class LocalReasoningProvider(Protocol):
    def explain(self, case_packet: Mapping[str, Any]) -> ReasoningResult:
        """Return unvalidated provider output for one bounded case packet."""
