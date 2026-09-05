"""Dedicated asynchronous worker for manual Foundation-Sec explanations."""

from __future__ import annotations

import time
import logging
from collections.abc import Callable
from typing import Any, Mapping, Protocol

from ..ai.evaluation import evaluate_case
from ..ai.reasoning import LocalReasoningProvider, ReasoningResult

logger = logging.getLogger(__name__)


class ExplainJobRepository(Protocol):
    def claim_pending(self) -> dict[str, Any] | None: ...
    def persist_completed(self, job_id: str, analysis: dict[str, Any], validation: dict[str, Any], provenance: dict[str, Any]) -> dict[str, Any] | None: ...
    def persist_failed(self, job_id: str, failure_code: str, validation_status: str, provider_status: str, provenance: dict[str, Any]) -> dict[str, Any] | None: ...


def _failure_status(result: ReasoningResult, report: dict[str, Any]) -> tuple[str, str]:
    if result.status == "too_large":
        return "too_large", "too_large"
    if result.status == "timeout":
        return "timeout", "timeout"
    if result.status in {"unavailable", "http_error"}:
        return "unavailable", result.status
    if report["unsupported_evidence_ids"]:
        return "unsupported_evidence", "invalid_response"
    return "invalid", result.status or "invalid_response"


class AiExplainWorker:
    def __init__(
        self,
        repository: ExplainJobRepository,
        provider: LocalReasoningProvider,
        packet_loader: Callable[[str], Mapping[str, Any] | None],
        provenance: Mapping[str, Any] | None = None,
        sleep: Callable[[float], None] = time.sleep,
        poll_interval_seconds: float = 1.0,
        stale_after_seconds: float = 300.0,
    ) -> None:
        self.repository = repository
        self.provider = provider
        self.packet_loader = packet_loader
        self.provenance = dict(provenance or {})
        self.sleep = sleep
        self.poll_interval_seconds = max(0.1, poll_interval_seconds)
        self.stale_after_seconds = max(1.0, stale_after_seconds)
        self._last_recovery = 0.0
        self._stop = False

    def stop(self) -> None:
        self._stop = True

    def run_once(self) -> bool:
        job = self.repository.claim_pending()
        if not job:
            return False
        job_id = str(job["job_id"])
        try:
            packet = job.get("case_packet_json") or self.packet_loader(str(job["case_id"]))
        except Exception as exc:
            self.repository.persist_failed(job_id, f"packet_loader:{type(exc).__name__}", "unavailable", "unavailable", self.provenance)
            return True
        if not packet or packet.get("evidence_fingerprint") != job["evidence_fingerprint"]:
            self.repository.persist_failed(job_id, "case_packet_unavailable_or_mismatch", "invalid", "unavailable", self.provenance)
            return True
        try:
            result = self.provider.explain(packet)
            report = evaluate_case(dict(packet), result, 0, include_analysis=True)
            if result.status == "received" and report["grounded"] and report["analysis"] is not None:
                self.repository.persist_completed(job_id, report["analysis"], report["validation"], self.provenance)
            else:
                validation_status, provider_status = _failure_status(result, report)
                self.repository.persist_failed(job_id, result.error or "analysis_validation_failed", validation_status, provider_status, self.provenance)
        except Exception as exc:
            self.repository.persist_failed(job_id, f"worker_error:{type(exc).__name__}", "invalid", "worker_error", self.provenance)
        return True

    def run_forever(self) -> None:
        while not self._stop:
            now = time.monotonic()
            if now - self._last_recovery >= self.stale_after_seconds:
                try:
                    self.repository.recover_stale_running(self.stale_after_seconds)
                except Exception as exc:
                    logger.warning("AI job recovery unavailable: %s", type(exc).__name__)
                self._last_recovery = now
            try:
                processed = self.run_once()
            except Exception as exc:
                logger.warning("AI worker database cycle unavailable: %s", type(exc).__name__)
                processed = False
            if not processed:
                self.sleep(self.poll_interval_seconds)
