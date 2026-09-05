"""Stable, detector-independent evidence contract."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Mapping


SUPPORTED_TYPES = frozenset({"rule", "rare_path", "rare_path_burst", "isolation_forest", "privacy", "reputation", "geo_network"})
SUPPORTED_SEVERITIES = frozenset({"supporting", "low", "medium", "high", "critical"})


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _stable_id(payload: Mapping[str, Any]) -> str:
    return f"ev_{hashlib.sha256(_canonical(payload).encode('utf-8')).hexdigest()[:24]}"


@dataclass(frozen=True)
class UnifiedEvidence:
    """Immutable evidence input; never owns classification or risk decisions."""

    source: str
    type: str
    severity: str
    observed: Mapping[str, Any]
    baseline: Mapping[str, Any]
    score_contribution: int
    observed_at: str
    description: str
    supporting_context: Mapping[str, Any] | None = None
    freshness: str | None = None
    mode: str | None = None
    evidence_id: str | None = None

    def __post_init__(self) -> None:
        if not self.source.strip() or not self.observed_at.strip() or not self.description.strip():
            raise ValueError("evidence source, observed_at and description must not be empty")
        if self.type not in SUPPORTED_TYPES:
            raise ValueError(f"unsupported evidence type: {self.type}")
        if self.severity not in SUPPORTED_SEVERITIES:
            raise ValueError(f"unsupported evidence severity: {self.severity}")
        if not isinstance(self.observed, Mapping) or not isinstance(self.baseline, Mapping):
            raise TypeError("evidence observed and baseline must be mappings")
        if not isinstance(self.score_contribution, int) or isinstance(self.score_contribution, bool):
            raise TypeError("evidence score_contribution must be an integer")
        expected = _stable_id(self._identity_payload())
        if self.evidence_id is not None and self.evidence_id != expected:
            raise ValueError("evidence_id does not match evidence content")
        object.__setattr__(self, "evidence_id", expected)

    def _identity_payload(self) -> dict[str, Any]:
        return {
            "source": self.source, "type": self.type, "severity": self.severity,
            "observed": dict(self.observed), "baseline": dict(self.baseline),
            "score_contribution": self.score_contribution, "observed_at": self.observed_at,
            "description": self.description, "supporting_context": dict(self.supporting_context or {}),
            "mode": self.mode,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._identity_payload(), "evidence_id": self.evidence_id, "freshness": self.freshness}
