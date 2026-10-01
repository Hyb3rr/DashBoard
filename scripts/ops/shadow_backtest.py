"""Compare saved V1 CasePacket scores with the offline shadow scorer."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from app.core.shadow_backtest import build_backtest_report


def _load_corpus(path: Path) -> dict[str, Any]:
    """Read one saved corpus or packet file without contacting runtime services."""
    try:
        content = path.read_bytes()
    except OSError:
        return {"source_file": path.name, "source_sha256": None, "manifest": {}, "load_error": "file_read_error"}

    digest = hashlib.sha256(content).hexdigest()
    try:
        payload = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {"source_file": path.name, "source_sha256": digest, "manifest": {}, "load_error": "invalid_json"}

    if isinstance(payload, list):
        return {"source_file": path.name, "source_sha256": digest, "manifest": {}, "cases": payload}
    if isinstance(payload, dict) and isinstance(payload.get("cases"), list):
        return {
            "source_file": path.name,
            "source_sha256": digest,
            "manifest": payload.get("manifest") or {},
            "cases": payload["cases"],
            "score_comparison_snapshots": payload.get("score_comparison_snapshots") or {},
        }
    if isinstance(payload, dict) and "subject" in payload:
        return {"source_file": path.name, "source_sha256": digest, "manifest": {}, "cases": [payload]}
    return {"source_file": path.name, "source_sha256": digest, "manifest": {}, "load_error": "unsupported_json_shape"}


def main() -> int:
    """Load saved JSON files and print a deterministic paired-score report."""
    parser = argparse.ArgumentParser(description="Offline V1-versus-shadow CasePacket backtest")
    parser.add_argument("corpora", nargs="+", type=Path, help="Saved CasePacket JSON corpus or packet files")
    args = parser.parse_args()
    corpora = [_load_corpus(path) for path in sorted(args.corpora, key=lambda item: item.name)]
    report = build_backtest_report(corpora)
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
