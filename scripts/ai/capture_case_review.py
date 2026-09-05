"""Capture independent, validated Foundation-Sec analysis per CasePacket."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import urlopen

from app.ai.evaluation import build_review_capture
from app.ai.providers.llama_cpp import LlamaCppHttpProvider
from scripts.ai.evaluate_cases import _load_corpus, benchmark_metadata


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _wait_ready(host: str, port: int, attempts: int, interval: float) -> None:
    for _ in range(attempts):
        try:
            with urlopen(f"http://{host}:{port}/health", timeout=1):
                return
        except OSError:
            time.sleep(interval)
    raise RuntimeError("llama-server did not become ready within bounded startup window")


def _free_port(host: str) -> int:
    with socket.socket() as probe:
        probe.bind((host, 0))
        return int(probe.getsockname()[1])


def _capture_one(case: dict, args: argparse.Namespace, metadata: dict) -> dict:
    packet = case.get("case_packet", case)
    case_id = str(packet.get("case_id") or "unknown-case")
    port = _free_port(args.host)
    command = [
        args.server, "--model", str(args.model_path), "--host", args.host,
        "--port", str(port), "--ctx-size", str(args.context_size),
        "--parallel", "1", "--n-gpu-layers", str(args.gpu_layers),
        "--threads", str(args.threads), "--reasoning-format", "deepseek",
    ]
    server = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    endpoint = f"http://{args.host}:{port}/v1/chat/completions"
    try:
        _wait_ready(args.host, port, args.ready_attempts, args.ready_interval)
        provider = LlamaCppHttpProvider(endpoint, args.model_name, args.timeout, args.max_tokens)
        started = time.perf_counter()
        result = provider.explain(packet)
        latency_ms = (time.perf_counter() - started) * 1000
        return build_review_capture(packet, result, latency_ms, args.run_id, metadata)
    except (OSError, RuntimeError) as exc:
        return {
            "case_id": case_id,
            "evidence_fingerprint": packet.get("evidence_fingerprint"),
            "capture_run_id": args.run_id,
            "latency_ms": None,
            "status": "failed",
            "analysis": None,
            "validation": {"grounded": False, "unsupported_evidence_ids": [], "duplicate_evidence_ids": False, "authority_violation": False},
            "error": str(exc),
            "provenance": metadata,
        }
    finally:
        if server.poll() is None:
            server.send_signal(signal.SIGTERM)
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser(description="Capture independent per-case local AI reviews")
    parser.add_argument("cases", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--model-path", type=Path, default=Path(os.environ["FOUNDATION_SEC_MODEL_PATH"]) if os.getenv("FOUNDATION_SEC_MODEL_PATH") else None)
    parser.add_argument("--server", default=os.getenv("LLAMA_SERVER_BIN", "llama-server"))
    parser.add_argument("--model-name", default=os.getenv("FOUNDATION_SEC_MODEL_NAME", "Foundation-Sec-8B-Reasoning"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--timeout", type=float, default=float(os.getenv("LOCAL_REASONING_TIMEOUT_SECONDS", "120")))
    parser.add_argument("--max-tokens", type=int, default=int(os.getenv("LOCAL_REASONING_MAX_TOKENS", "256")))
    parser.add_argument("--context-size", type=int, default=int(os.getenv("FOUNDATION_SEC_CONTEXT_SIZE", "4096")))
    parser.add_argument("--gpu-layers", type=int, default=int(os.getenv("FOUNDATION_SEC_GPU_LAYERS", "0")))
    parser.add_argument("--threads", type=int, default=int(os.getenv("FOUNDATION_SEC_THREADS", "6")))
    parser.add_argument("--ready-attempts", type=int, default=60)
    parser.add_argument("--ready-interval", type=float, default=1.0)
    args = parser.parse_args()
    if args.model_path is None or not args.model_path.is_file():
        parser.error("--model-path must point to the local GGUF model")
    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        parser.error("capture server must bind to localhost")

    cases, manifest = _load_corpus(args.cases)
    metadata = benchmark_metadata(manifest, args.model_path, args.timeout, cases)
    metadata.update({
        "capture_format_version": "ai-4c1-v1",
        "capture_run_id": args.run_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    args.output_dir.mkdir(parents=True, exist_ok=True)
    failures = 0
    for item in cases:
        packet = item.get("case_packet", item)
        case_id = str(packet.get("case_id") or "unknown-case")
        target = args.output_dir / f"{case_id}.json"
        if target.exists():
            raise FileExistsError(f"refusing to overwrite existing capture: {target}")
        artifact = _capture_one(item, args, metadata)
        target.write_text(json.dumps(artifact, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        failures += artifact["status"] != "completed" or not artifact["validation"]["grounded"]
        print(json.dumps({"case_id": case_id, "status": artifact["status"], "path": str(target)}), flush=True)
    manifest_path = args.output_dir / "manifest.json"
    if manifest_path.exists():
        raise FileExistsError(f"refusing to overwrite existing capture manifest: {manifest_path}")
    manifest_payload = {"capture_run_id": args.run_id, "case_count": len(cases), "failed_cases": failures, "metadata": metadata}
    manifest_payload["manifest_sha256"] = hashlib.sha256(_canonical(manifest_payload).encode("utf-8")).hexdigest()
    manifest_path.write_text(json.dumps(manifest_payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
