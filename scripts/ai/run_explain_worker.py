"""Run one isolated AI explain worker process."""

from __future__ import annotations

import argparse
import json
import os
import signal
from pathlib import Path

from dotenv import load_dotenv

from app.ai.providers.llama_cpp import PROMPT_SCHEMA_VERSION, LlamaCppHttpProvider
from app.services.ai_explain_worker import AiExplainWorker
from app.db.ai_jobs import AiExplainJobRepository


def _load_packets(path: Path) -> dict[str, dict]:
    """Load CasePackets into a case-ID lookup map."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    cases = payload.get("cases", []) if isinstance(payload, dict) else payload
    return {str(item.get("case_packet", item)["case_id"]): item.get("case_packet", item) for item in cases}


def _setting_float(name: str, default: float) -> float:
    """Read a floating-point environment setting with a fallback."""
    try:
        return float(os.getenv(name, str(default)))
    except ValueError:
        return default


def _endpoint_default() -> str:
    """Resolve the configured local model endpoint URL."""
    explicit = os.getenv("LOCAL_REASONING_ENDPOINT", "").strip()
    if explicit:
        return explicit
    base = os.getenv("LOCAL_REASONING_BASE_URL", "").strip()
    if base:
        return base.rstrip("/") + ("" if base.endswith("/chat/completions") else "/v1/chat/completions")
    port = os.getenv("LOCAL_REASONING_PORT", "8081").strip() or "8081"
    return f"http://127.0.0.1:{port}/v1/chat/completions"


def main() -> int:
    """Configure and run the dedicated AI explanation worker."""
    load_dotenv()
    parser = argparse.ArgumentParser(description="Run dedicated local AI explain worker")
    parser.add_argument("--packets", type=Path, required=True, help="Bounded CasePacket corpus/read model")
    parser.add_argument("--endpoint", default=None)
    parser.add_argument("--model", default=None)
    parser.add_argument("--timeout", type=float, default=None)
    parser.add_argument("--once", action="store_true", help="Claim at most one job")
    parser.add_argument("--poll-interval", type=float, default=None)
    parser.add_argument("--stale-after", type=float, default=None, help="Recover abandoned jobs after this many seconds")
    args = parser.parse_args()
    endpoint = args.endpoint or _endpoint_default()
    model = args.model or os.getenv("FOUNDATION_SEC_MODEL_NAME", "Foundation-Sec-8B-Reasoning")
    timeout = args.timeout if args.timeout is not None else _setting_float("LOCAL_REASONING_TIMEOUT_SECONDS", 180.0)
    poll_interval = args.poll_interval if args.poll_interval is not None else _setting_float("AI_EXPLAIN_POLL_INTERVAL_SECONDS", 1.0)
    stale_after = args.stale_after if args.stale_after is not None else _setting_float("AI_EXPLAIN_STALE_AFTER_SECONDS", timeout + 45.0)
    packets = _load_packets(args.packets)
    worker = AiExplainWorker(
        AiExplainJobRepository(),
        LlamaCppHttpProvider(endpoint, model, timeout),
        packets.get,
        provenance={
            "provider": "llama_cpp",
            "model": model,
            "endpoint": endpoint,
            "configured_timeout_seconds": timeout,
            "prompt_schema_version": PROMPT_SCHEMA_VERSION,
        },
        poll_interval_seconds=poll_interval,
        stale_after_seconds=stale_after,
    )
    signal.signal(signal.SIGTERM, lambda *_: worker.stop())
    signal.signal(signal.SIGINT, lambda *_: worker.stop())
    if args.once:
        worker.run_once()
    else:
        worker.run_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
