"""Validate and aggregate human quality scores for a manual-review packet."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from app.ai.manual_review import aggregate_manual_scores


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def main() -> int:
    parser = argparse.ArgumentParser(description="Aggregate manual AI reasoning scores")
    parser.add_argument("review_packet", type=Path)
    parser.add_argument("scores", type=Path, help="JSON object with a scores array, or a JSON score array")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error(f"refusing to overwrite existing score report: {args.output}")
    packet = json.loads(args.review_packet.read_text(encoding="utf-8"))
    raw_scores = json.loads(args.scores.read_text(encoding="utf-8"))
    scores = raw_scores.get("scores") if isinstance(raw_scores, dict) else raw_scores
    if not isinstance(scores, list):
        parser.error("scores must be a JSON array or object containing scores")
    result = aggregate_manual_scores(packet, scores)
    report = {"format_version": "ai-4c3-v1", "review_packet_sha256": hashlib.sha256(_canonical(packet).encode("utf-8")).hexdigest(), "aggregate": result}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({key: report["aggregate"][key] for key in ("case_count", "median_total_quality", "overclaiming_count", "overclaiming_rate")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
