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


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _load_corpus(path: Path) -> tuple[list[dict], dict]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, list):
        return payload, {}
    if isinstance(payload, dict) and isinstance(payload.get("cases"), list):
        return payload["cases"], payload.get("manifest") or {}
    raise ValueError("cases file must contain a JSON array or a corpus object with cases")


def _sha256(path: Path) -> str | None:
    if not path or not path.exists():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _runtime_version(binary: str) -> str:
    try:
        result = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=5, check=False)
        return result.stdout.strip() or result.stderr.strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unavailable"


def benchmark_metadata(corpus_manifest: dict, model_path: Path | None, timeout: float, cases: list[dict]) -> dict:
    prompt_hash = hashlib.sha256(SYSTEM_PROMPT.encode("utf-8")).hexdigest()
    schema_hash = hashlib.sha256(_canonical([build_analysis_schema([str(item["evidence_id"]) for item in case.get("evidence", []) if isinstance(item, dict) and item.get("evidence_id")]) for case in cases]).encode("utf-8")).hexdigest()
    return {
        "corpus_sha256": corpus_manifest.get("corpus_sha256"),
        "corpus_packet_count": corpus_manifest.get("packet_count"),
        "model_sha256": _sha256(model_path) if model_path else None,
        "llama_cpp_version": _runtime_version(os.getenv("LLAMA_SERVER_BIN", "llama-server")),
        "prompt_sha256": prompt_hash,
        "schema_sha256": schema_hash,
        "schema_scope": "dynamic_per_case_packet",
        "inference_view_version": INFERENCE_VIEW_VERSION,
        "inference_view_sha256": hashlib.sha256(_canonical(INFERENCE_VIEW_CONFIG).encode("utf-8")).hexdigest(),
        "context_size": int(os.getenv("FOUNDATION_SEC_CONTEXT_SIZE", "4096")),
        "temperature": 0,
        "max_tokens": int(os.getenv("LOCAL_REASONING_MAX_TOKENS", "256")),
        "gpu_layers": int(os.getenv("FOUNDATION_SEC_GPU_LAYERS", "0")),
        "timeout_seconds": timeout,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate local case explanations")
    parser.add_argument("cases", type=Path, help="JSON array of CasePacket objects")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--endpoint", default="http://127.0.0.1:8081/v1/chat/completions")
    parser.add_argument("--model", default="Foundation-Sec-8B-Reasoning")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--model-path", type=Path, default=Path(os.getenv("FOUNDATION_SEC_MODEL_PATH", "")) if os.getenv("FOUNDATION_SEC_MODEL_PATH") else None)
    parser.add_argument("--capture-analysis", action="store_true", help="Persist validated parsed analysis for manual review")
    parser.add_argument("--run-id", default="run-003-review-capture")
    args = parser.parse_args()
    cases, manifest = _load_corpus(args.cases)
    report = evaluate_corpus(cases, LlamaCppHttpProvider(args.endpoint, args.model, args.timeout), args.capture_analysis)
    report["benchmark_metadata"] = benchmark_metadata(manifest, args.model_path, args.timeout, cases)
    if args.capture_analysis:
        report["capture_metadata"] = {
            "run_id": args.run_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "capture_format_version": "ai-4a0-v1",
            "raw_provider_response_saved": False,
        }
        report["capture_metadata"]["report_sha256"] = hashlib.sha256(_canonical(report).encode("utf-8")).hexdigest()
    encoded = json.dumps(report, indent=2, ensure_ascii=False)
    if args.report:
        args.report.write_text(encoded + "\n", encoding="utf-8")
    print(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
