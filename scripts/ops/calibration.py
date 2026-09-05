"""CLI wrapper for classification calibration."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from app.core.calibration import csv_text, evaluate_csv


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate manually labeled IP classifications")
    parser.add_argument("csv_path")
    args = parser.parse_args()
    print(json.dumps(evaluate_csv(args.csv_path), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
