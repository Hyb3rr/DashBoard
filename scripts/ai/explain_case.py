"""Manual local reasoning sandbox client; never touches PostgreSQL or ClickHouse."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.ai.providers.llama_cpp import LlamaCppHttpProvider


def main() -> int:
    parser = argparse.ArgumentParser(description="Send one CasePacket to local llama.cpp")
    parser.add_argument("case_packet", type=Path)
    parser.add_argument("--endpoint", default="http://127.0.0.1:8080/v1/chat/completions")
    parser.add_argument("--model", default="local")
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()
    packet = json.loads(args.case_packet.read_text(encoding="utf-8"))
    result = LlamaCppHttpProvider(args.endpoint, args.model, args.timeout).explain(packet)
    print(json.dumps({"status": result.status, "evidence_fingerprint": result.evidence_fingerprint, "raw_response": result.raw_response, "error": result.error}, indent=2, ensure_ascii=False))
    return 0 if result.status == "received" else 1


if __name__ == "__main__":
    raise SystemExit(main())
