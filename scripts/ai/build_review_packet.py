"""Build a deterministic manual-review artifact from independent captures."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from app.ai.manual_review import build_manual_review_packet
from scripts.ai.evaluate_cases import _load_corpus


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build manual review packet from validated AI captures")
    parser.add_argument("cases", type=Path)
    parser.add_argument("--capture-dir", type=Path, action="append", required=True, help="Capture attempt directory; order is earliest first")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error(f"refusing to overwrite existing review packet: {args.output}")
    cases, manifest = _load_corpus(args.cases)
    for directory in args.capture_dir:
        if not directory.is_dir():
            parser.error(f"capture directory does not exist: {directory}")
    packet = build_manual_review_packet(cases, args.capture_dir, {
        "corpus_sha256": manifest.get("corpus_sha256"),
        "corpus_packet_count": manifest.get("packet_count"),
        "capture_attempts": [str(path) for path in args.capture_dir],
    })
    packet["packet_sha256"] = hashlib.sha256(_canonical(packet).encode("utf-8")).hexdigest()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(packet, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(packet["coverage"], sort_keys=True))
    return 0 if packet["coverage"]["unavailable_cases"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
