"""Build a local, untracked CasePacket corpus from the live PG/CH read planes."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from app.core.evidence import UnifiedEvidence
from app.db import clickhouse
from app.db.repositories import AiRepository, StateRepository
from app.services.case_packets import build_case_packet
from app.config import settings


BUILDER_VERSION = "ai-3b0-v1"
DEFAULT_LIMIT = 30


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _iso(value: Any, fallback: datetime) -> str:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    text = str(value or "")
    return text or fallback.isoformat()


def _rule_evidence(item: dict[str, Any], observed_at: str) -> dict[str, Any]:
    return UnifiedEvidence(
        source="rule",
        type="rule",
        severity=str(item.get("severity") or "supporting"),
        observed={"rule_id": str(item.get("id") or ""), "points": int(item.get("points") or 0)},
        baseline={},
        score_contribution=int(item.get("points") or 0),
        observed_at=observed_at,
        description=str(item.get("evidence") or item.get("name") or "Rule fired"),
        supporting_context={"name": str(item.get("name") or ""), "mitre_technique": item.get("mitre_technique")},
    ).to_dict()


def _evidence(row: dict[str, Any], ai_score: dict[str, Any] | None, snapshot_at: datetime) -> list[dict[str, Any]]:
    observation = row.get("observation_payload") or {}
    observed_at = _iso(observation.get("evaluated_at_24h") or observation.get("evaluated_at"), snapshot_at)
    values: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in observation.get("detections_24h") or observation.get("detections") or []:
        if not isinstance(item, dict):
            continue
        value = _rule_evidence(item, observed_at)
        if value["evidence_id"] not in seen:
            values.append(value)
            seen.add(value["evidence_id"])
    for item in observation.get("rare_path_evidence") or []:
        if not isinstance(item, dict) or not item.get("evidence_id"):
            continue
        value = dict(item)
        if value["evidence_id"] not in seen:
            values.append(value)
            seen.add(value["evidence_id"])
    if ai_score and ai_score.get("ai_anomaly_score") is not None:
        value = UnifiedEvidence(
            source="isolation_forest", type="isolation_forest", severity="supporting",
            observed={"anomaly_score": float(ai_score["ai_anomaly_score"])}, baseline={},
            score_contribution=0, observed_at=_iso(ai_score.get("scored_at"), snapshot_at),
            description="Isolation Forest anomaly score from persisted AI state.",
            supporting_context={"model_key": ai_score.get("model_key")}, mode="persisted_v1",
        ).to_dict()
        if value["evidence_id"] not in seen:
            values.append(value)
    return values


def _reasons(row: dict[str, Any], evidence: list[dict[str, Any]], high_volume_threshold: int) -> list[str]:
    observation = row.get("observation_payload") or {}
    reasons = [f"classification_{str(row.get('label') or 'unknown').lower()}"]
    types = {item.get("type") for item in evidence}
    if "rule" in types:
        reasons.append("rule_fired")
    if "rare_path" in types or "rare_path_burst" in types:
        reasons.append("rare_path")
    if "isolation_forest" in types:
        reasons.append("if_anomaly")
    requests = int(observation.get("requests") or observation.get("recent_requests") or 0)
    errors = int(observation.get("status_4xx") or observation.get("recent_status_4xx") or 0)
    if requests and errors / requests >= 0.5:
        reasons.append("high_404")
    if requests >= high_volume_threshold:
        reasons.append("high_volume")
    return reasons


def build_corpus(
    rows: Iterable[dict[str, Any]],
    traffic_for_ip: Callable[[datetime, datetime, int, str, str], dict[str, Any]],
    snapshot_at: datetime,
    ai_scores: dict[str, dict[str, Any]] | None = None,
    limit: int = DEFAULT_LIMIT,
    high_volume_threshold: int = 1000,
) -> dict[str, Any]:
    """Build deterministic packets from one PG snapshot and bounded CH reads."""
    end = snapshot_at.astimezone(timezone.utc)
    start = end - timedelta(hours=24)
    candidates = []
    for row in rows:
        ip = str(row.get("identity_ip") or row.get("ip") or "")
        if not ip:
            continue
        evidence = _evidence(row, (ai_scores or {}).get(ip), end)
        reasons = _reasons(row, evidence, high_volume_threshold)
        candidates.append((len(reasons), ip, row, evidence, reasons))
    candidates.sort(key=lambda item: (-item[0], item[1]))
    selected = candidates[: max(1, min(int(limit), 30))]
    cases = []
    selection = {}
    for _, ip, row, evidence, reasons in selected:
        observation = row.get("observation_payload") or {}
        traffic = traffic_for_ip(start, end, 3600, ip, settings.DATASET_LIVE_ID)
        total = int(traffic.get("total_requests") or 0)
        statuses = traffic.get("status_codes") or {}
        cases.append(build_case_packet(
            ip=ip,
            classification={"label": row.get("label") or "unknown", "risk_score": row.get("classification_score") or 0, "confidence": row.get("classification_confidence") or 0},
            window={"start": start.isoformat(), "end": end.isoformat()},
            traffic_summary={"requests": total, "unique_paths": len(traffic.get("top_paths") or []), "status_4xx_ratio": round(int(statuses.get("4xx") or 0) / total, 4) if total else 0},
            evidence=evidence,
            representative_requests=traffic.get("recent_requests") or [],
        ))
        selection[ip] = reasons
    corpus_hash = hashlib.sha256(_canonical(cases).encode("utf-8")).hexdigest()
    return {"manifest": {"corpus_created_at": end.isoformat(), "source_window": {"start": start.isoformat(), "end": end.isoformat()}, "corpus_sha256": corpus_hash, "builder_version": BUILDER_VERSION, "packet_count": len(cases), "selection_reason": selection}, "cases": cases}


def main() -> int:
    parser = argparse.ArgumentParser(description="Build an untracked real CasePacket corpus")
    parser.add_argument("--output", type=Path, default=Path("data/ai/corpora/foundation-sec-real.json"))
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    parser.add_argument("--high-volume-threshold", type=int, default=1000)
    args = parser.parse_args()
    snapshot_at = datetime.now(timezone.utc)
    result = StateRepository().page(1, 5000, "threat_signal_score", "desc")
    rows = result["rows"]
    scores = {str(item["ip"]): item for item in AiRepository().scores([str(row.get("identity_ip") or row.get("ip")) for row in rows if row.get("identity_ip") or row.get("ip")])}
    corpus = build_corpus(rows, clickhouse.traffic_for_ip, snapshot_at, scores, args.limit, args.high_volume_threshold)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(corpus, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(corpus["manifest"], indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
