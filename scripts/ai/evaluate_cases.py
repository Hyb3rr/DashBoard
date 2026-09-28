"""Run offline case corpus evaluation through a local reasoning provider."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from app.ai.evaluation import evaluate_corpus
from app.ai.inference_view import INFERENCE_VIEW_CONFIG, INFERENCE_VIEW_VERSION
from app.ai.providers.llama_cpp import ANALYSIS_SCHEMA, SYSTEM_PROMPT, LlamaCppHttpProvider, build_analysis_schema

OFFLINE_EVALUATION_TIMEOUT_SECONDS = 30.0
DEFAULT_CONFIGURED_CONTEXT_SIZE = 8192


def _canonical(value):
    """Serialize values deterministically for content fingerprinting."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _load_corpus(path: Path) -> tuple[list[dict], dict]:
    """Load a case array or a corpus object with optional manifest metadata."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, list):
        return payload, {}
    if isinstance(payload, dict) and isinstance(payload.get("cases"), list):
        return payload["cases"], payload.get("manifest") or {}
    raise ValueError("cases file must contain a JSON array or a corpus object with cases")


def _sha256(path: Path) -> str | None:
    """Hash a file incrementally, returning None when it is unavailable."""
    if not path or not path.exists():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _runtime_version(binary: str) -> str:
    """Return the local inference binary version without failing the benchmark."""
    try:
        result = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=5, check=False)
        return result.stdout.strip() or result.stderr.strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unavailable"


def _schema_hash(cases: list[dict]) -> str:
    """Fingerprint the dynamic analysis schema generated for every case."""
    schemas = []
    for case in cases:
        evidence_ids = [
            str(item["evidence_id"])
            for item in case.get("evidence", [])
            if isinstance(item, dict) and item.get("evidence_id")
        ]
        schemas.append(build_analysis_schema(evidence_ids))
    return hashlib.sha256(_canonical(schemas).encode("utf-8")).hexdigest()


def benchmark_metadata(
    corpus_manifest: dict,
    model_path: Path | None,
    timeout: float,
    cases: list[dict],
    *,
    model_name: str | None = None,
    max_tokens: int | None = None,
    context_size: int | None = None,
    gpu_layers: int | None = None,
    runtime_profile: str = "offline_evaluation",
) -> dict:
    """Record reproducibility metadata for the corpus, prompt, model, and runtime."""
    prompt_hash = hashlib.sha256(SYSTEM_PROMPT.encode("utf-8")).hexdigest()
    return {
        "corpus_sha256": corpus_manifest.get("corpus_sha256"),
        "corpus_packet_count": corpus_manifest.get("packet_count"),
        "model_sha256": _sha256(model_path) if model_path else None,
        "llama_cpp_version": _runtime_version(os.getenv("LLAMA_SERVER_BIN", "llama-server")),
        "prompt_sha256": prompt_hash,
        "schema_sha256": _schema_hash(cases),
        "schema_scope": "dynamic_per_case_packet",
        "inference_view_version": INFERENCE_VIEW_VERSION,
        "inference_view_sha256": hashlib.sha256(_canonical(INFERENCE_VIEW_CONFIG).encode("utf-8")).hexdigest(),
        "runtime_profile": runtime_profile,
        "model_name": model_name,
        "context_size": context_size if context_size is not None else int(os.getenv("FOUNDATION_SEC_CONTEXT_SIZE", str(DEFAULT_CONFIGURED_CONTEXT_SIZE))),
        "temperature": 0,
        "max_tokens": max_tokens if max_tokens is not None else int(os.getenv("LOCAL_REASONING_MAX_TOKENS", "768")),
        "gpu_layers": gpu_layers if gpu_layers is not None else int(os.getenv("FOUNDATION_SEC_GPU_LAYERS", "0")),
        "timeout_seconds": timeout,
    }


def _capture_metadata(report: dict, run_id: str) -> dict:
    """Describe a manual-review capture and hash the report before self-reference."""
    metadata = {
        "run_id": run_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "capture_format_version": "ai-4a0-v1",
        "raw_provider_response_saved": False,
    }
    metadata["report_sha256"] = hashlib.sha256(_canonical(report).encode("utf-8")).hexdigest()
    return metadata


def _build_report(args: argparse.Namespace) -> dict:
    """Run corpus evaluation and attach reproducibility and capture metadata."""
    cases, manifest = _load_corpus(args.cases)
    provider = LlamaCppHttpProvider(args.endpoint, args.model, args.timeout)
    report = evaluate_corpus(
        cases,
        provider,
        args.capture_analysis,
    )
    report["benchmark_metadata"] = benchmark_metadata(
        manifest,
        args.model_path,
        args.timeout,
        cases,
        model_name=args.model,
        max_tokens=provider.max_tokens,
        context_size=int(os.getenv("FOUNDATION_SEC_CONTEXT_SIZE", str(DEFAULT_CONFIGURED_CONTEXT_SIZE))),
        gpu_layers=int(os.getenv("FOUNDATION_SEC_GPU_LAYERS", "0")),
    )
    if args.capture_analysis:
        report["capture_metadata"] = _capture_metadata(report, args.run_id)
    return report


def main() -> int:
    """Parse evaluation options, run the corpus, and print or save its report."""
    parser = argparse.ArgumentParser(description="Evaluate local case explanations")
    parser.add_argument("cases", type=Path, help="JSON array of CasePacket objects")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--endpoint", default="http://127.0.0.1:8081/v1/chat/completions")
    parser.add_argument("--model", default="Foundation-Sec-8B-Reasoning")
    parser.add_argument("--timeout", type=float, default=OFFLINE_EVALUATION_TIMEOUT_SECONDS)
    parser.add_argument("--model-path", type=Path, default=Path(os.getenv("FOUNDATION_SEC_MODEL_PATH", "")) if os.getenv("FOUNDATION_SEC_MODEL_PATH") else None)
    parser.add_argument("--capture-analysis", action="store_true", help="Persist validated parsed analysis for manual review")
    parser.add_argument("--run-id", default="run-003-review-capture")
    args = parser.parse_args()
    report = _build_report(args)
    encoded = json.dumps(report, indent=2, ensure_ascii=False)
    if args.report:
        args.report.write_text(encoded + "\n", encoding="utf-8")
    print(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
