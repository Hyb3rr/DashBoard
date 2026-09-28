"""Dedicated asynchronous worker for manual Foundation-Sec explanations."""

from __future__ import annotations

import time
import logging
from collections.abc import Callable
from time import perf_counter
from typing import Any, Mapping, Protocol

from ..ai.evaluation import evaluate_case
from ..ai.reasoning import LocalReasoningProvider, ReasoningResult

logger = logging.getLogger(__name__)

DEFAULT_STALE_AFTER_SECONDS = 75.0
DEFAULT_PROVIDER_FAILURE_THRESHOLD = 3
DEFAULT_PROVIDER_FAILURE_BACKOFF_SECONDS = 10.0
_SAFE_PROVIDER_DIAGNOSTICS = {
    "estimated_input_tokens",
    "configured_input_budget_tokens",
    "context_input_limit_tokens",
}


class ExplainJobRepository(Protocol):
    def claim_pending(self) -> dict[str, Any] | None:
        """Atomically claim one pending explanation job."""
        ...

    def persist_completed(self, job_id: str, analysis: dict[str, Any], validation: dict[str, Any], provenance: dict[str, Any]) -> dict[str, Any] | None:
        """Persist a validated explanation and its provenance."""
        ...

    def persist_failed(self, job_id: str, failure_code: str, validation_status: str, provider_status: str, provenance: dict[str, Any]) -> dict[str, Any] | None:
        """Persist a failed explanation with structured failure status."""
        ...

    def persist_abstained(self, job_id: str, reason: str, provenance: dict[str, Any]) -> dict[str, Any] | None:
        """Persist an intentional local-reasoning budget abstention."""
        ...


def _failure_status(result: ReasoningResult, report: dict[str, Any]) -> tuple[str, str]:
    """Map provider and grounding failures to persisted job status values."""
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
        stale_after_seconds: float = DEFAULT_STALE_AFTER_SECONDS,
        provider_failure_threshold: int = DEFAULT_PROVIDER_FAILURE_THRESHOLD,
        provider_failure_backoff_seconds: float = DEFAULT_PROVIDER_FAILURE_BACKOFF_SECONDS,
    ) -> None:
        """Configure dependencies, polling policy, and provider backoff state."""
        self.repository = repository
        self.provider = provider
        self.packet_loader = packet_loader
        self.provenance = dict(provenance or {})
        self.sleep = sleep
        self.poll_interval_seconds = max(0.1, poll_interval_seconds)
        self.stale_after_seconds = max(1.0, stale_after_seconds)
        self.provider_failure_threshold = max(1, int(provider_failure_threshold))
        self.provider_failure_backoff_seconds = max(0.1, provider_failure_backoff_seconds)
        self._consecutive_provider_failures = 0
        self._provider_backoff_until = 0.0
        self._last_recovery = 0.0
        self._stop = False

    def _provenance(self, job: Mapping[str, Any], latency_ms: float = 0.0) -> dict[str, Any]:
        """Build stable model and evidence provenance for one job attempt."""
        result = dict(self.provenance)
        result.setdefault("provider", "local_reasoning")
        result.setdefault("model", "unknown")
        result.setdefault("configured_timeout_seconds", None)
        result.setdefault("prompt_schema_version", "unknown")
        result["evidence_fingerprint"] = job.get("evidence_fingerprint")
        result["latency_ms"] = round(max(0.0, latency_ms), 2)
        return result

    def _merge_provider_diagnostics(self, provenance: dict[str, Any], result: ReasoningResult) -> None:
        """Copy only bounded numeric calibration metadata from the provider."""
        diagnostics = result.diagnostics
        if not isinstance(diagnostics, Mapping):
            return
        for key in _SAFE_PROVIDER_DIAGNOSTICS:
            value = diagnostics.get(key)
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                provenance[key] = value

    def stop(self) -> None:
        """Signal the polling loop to finish after its current operation."""
        self._stop = True

    def run_once(self) -> bool:
        """Claim and process at most one explanation job."""
        job = self.repository.claim_pending()
        if not job:
            return False
        job_id = str(job["job_id"])
        started = perf_counter()
        try:
            packet = job.get("case_packet_json") or self.packet_loader(str(job["case_id"]))
        except Exception as exc:
            self.repository.persist_failed(job_id, f"packet_loader:{type(exc).__name__}", "unavailable", "unavailable", self._provenance(job, (perf_counter() - started) * 1000))
            return True
        if not packet or packet.get("evidence_fingerprint") != job["evidence_fingerprint"]:
            self.repository.persist_failed(job_id, "case_packet_unavailable_or_mismatch", "invalid", "unavailable", self._provenance(job, (perf_counter() - started) * 1000))
            return True
        try:
            result = self.provider.explain(packet)
            latency_ms = (perf_counter() - started) * 1000
            provenance = self._provenance(job, latency_ms)
            self._merge_provider_diagnostics(provenance, result)
            if result.status == "abstained":
                self.repository.persist_abstained(job_id, "local_reasoning_budget_exceeded", provenance)
                return True
            report = evaluate_case(dict(packet), result, latency_ms, include_analysis=True)
            self._record_provider_result(result.status)
            if result.status == "received" and report["grounded"] and report["analysis"] is not None:
                self.repository.persist_completed(job_id, report["analysis"], report["validation"], provenance)
            else:
                validation_status, provider_status = _failure_status(result, report)
                self.repository.persist_failed(job_id, result.error or "analysis_validation_failed", validation_status, provider_status, provenance)
        except Exception as exc:
            self.repository.persist_failed(job_id, f"worker_error:{type(exc).__name__}", "invalid", "worker_error", self._provenance(job, (perf_counter() - started) * 1000))
        return True

    def _record_provider_result(self, status: str) -> None:
        """Update consecutive provider failure count and backoff deadline."""
        if status in {"timeout", "unavailable", "http_error"}:
            self._consecutive_provider_failures += 1
            if self._consecutive_provider_failures >= self.provider_failure_threshold:
                self._provider_backoff_until = time.monotonic() + self.provider_failure_backoff_seconds
            return
        if status == "received":
            self._consecutive_provider_failures = 0
            self._provider_backoff_until = 0.0

    def run_forever(self) -> None:
        """Poll jobs, recover stale work, and back off after provider failures."""
        while not self._stop:
            now = time.monotonic()
            if now < self._provider_backoff_until:
                self.sleep(self._provider_backoff_until - now)
                continue
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
