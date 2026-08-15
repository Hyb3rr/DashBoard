"""Small, dependency-free workflow for validating IP classifications."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Iterable


FIELDS = (
    "ip", "predicted_label", "predicted_score", "predicted_confidence",
    "behavior_a", "identity_b", "trust_c", "region_d",
    "country", "country_code", "city", "asn", "organization", "network_type",
    "is_tor", "is_vpn", "is_proxy", "is_hosting", "behavior_score", "requests",
    "status_4xx", "unique_paths", "wp_login_requests", "sensitive_probe_requests",
    "effective_risk_score", "ai_e", "ai_anomaly_score", "anomalous_windows",
    "windows_seen", "model_mode", "ai_confidence", "ai_confidence_level",
    "ai_score_delta", "ai_score_reason", "ai_model_version", "human_label", "notes",
)
LABELS = {"good", "watch", "bad", "unknown"}


def _row(item: dict) -> dict:
    classification = item.get("classification") or {}
    row = {field: "" for field in FIELDS}
    row.update({
        "ip": item.get("ip", ""),
        "predicted_label": classification.get("label", "unknown"),
        "predicted_score": classification.get("score", ""),
        "predicted_confidence": classification.get("confidence", ""),
        "behavior_a": (classification.get("score_breakdown") or {}).get("behavior_a", ""),
        "identity_b": (classification.get("score_breakdown") or {}).get("identity_b", ""),
        "trust_c": (classification.get("score_breakdown") or {}).get("trust_c", ""),
        "region_d": (classification.get("score_breakdown") or {}).get("region_d", ""),
        "country": item.get("country", ""),
        "country_code": item.get("country_code", ""),
        "city": item.get("city", ""),
        "asn": item.get("asn", ""),
        "organization": item.get("organization", ""),
        "network_type": item.get("network_type", ""),
        "is_tor": item.get("is_tor", ""),
        "is_vpn": item.get("is_vpn", ""),
        "is_proxy": item.get("is_proxy", ""),
        "is_hosting": item.get("is_hosting", ""),
        "behavior_score": item.get("behavior_score", ""),
        "requests": item.get("requests", ""),
        "status_4xx": item.get("status_4xx", ""),
        "unique_paths": item.get("unique_paths", ""),
        "wp_login_requests": item.get("wp_login_requests", ""),
        "sensitive_probe_requests": item.get("sensitive_probe_requests", ""),
        "effective_risk_score": item.get("effective_risk_score", ""),
        "ai_e": (classification.get("score_breakdown") or {}).get("ai_e", ""),
        "ai_anomaly_score": (item.get("ai_profile") or {}).get("ai_anomaly_score", ""),
        "anomalous_windows": (item.get("ai_profile") or {}).get("anomalous_windows", ""),
        "windows_seen": (item.get("ai_profile") or {}).get("windows_seen", ""),
        "model_mode": (item.get("ai_profile") or {}).get("model_mode", ""),
        "ai_confidence": (item.get("ai_profile") or {}).get("confidence", ""),
        "ai_confidence_level": (item.get("ai_profile") or {}).get("confidence_level", ""),
        "ai_score_delta": (item.get("ai_profile") or {}).get("score_delta", ""),
        "ai_score_reason": (item.get("ai_profile") or {}).get("score_reason", ""),
        "ai_model_version": (item.get("ai_profile") or {}).get("model_version", ""),
    })
    return row


def csv_text(items: Iterable[dict]) -> str:
    rows = [_row(item) for item in items]
    output = []
    from io import StringIO
    stream = StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=FIELDS)
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue()


def evaluate_csv(path: str | Path) -> dict:
    """Evaluate non-empty human_label values against predicted labels."""
    confusion = {expected: {actual: 0 for actual in sorted(LABELS)} for expected in sorted(LABELS)}
    mismatches = []
    labeled = 0
    with Path(path).open(newline="", encoding="utf-8-sig") as stream:
        for row in csv.DictReader(stream):
            expected = (row.get("human_label") or "").strip().lower()
            predicted = (row.get("predicted_label") or "unknown").strip().lower()
            if not expected:
                continue
            if expected not in LABELS:
                raise ValueError(f"Unsupported human_label {expected!r}; use good, watch, bad, or unknown")
            if predicted not in LABELS:
                predicted = "unknown"
            labeled += 1
            confusion[expected][predicted] += 1
            if expected != predicted:
                mismatches.append({"ip": row.get("ip", ""), "expected": expected, "predicted": predicted})

    correct = sum(confusion[label][label] for label in LABELS)
    metrics = {}
    for label in sorted(LABELS):
        true_positive = confusion[label][label]
        predicted_total = sum(confusion[expected][label] for expected in LABELS)
        actual_total = sum(confusion[label].values())
        metrics[label] = {
            "precision": round(true_positive / predicted_total, 3) if predicted_total else None,
            "recall": round(true_positive / actual_total, 3) if actual_total else None,
            "support": actual_total,
        }
    return {
        "labeled": labeled,
        "correct": correct,
        "accuracy": round(correct / labeled, 3) if labeled else None,
        "confusion_matrix": confusion,
        "per_label": metrics,
        "mismatches": mismatches,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate manually labeled IP classifications")
    parser.add_argument("csv_path")
    args = parser.parse_args()
    print(json.dumps(evaluate_csv(args.csv_path), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
