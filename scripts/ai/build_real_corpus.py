"""Build a local, untracked CasePacket corpus from the live PG/CH read planes."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from app.core.evidence import UnifiedEvidence
from app.core.classification_provenance import classification_input_provenance
from app.db import clickhouse
from app.db.repositories import AiRepository, StateRepository
from app.services.case_packets import build_case_packet
from app.config import settings


BUILDER_VERSION = "ai-3b0-v3"
DEFAULT_LIMIT = 30
CLASSIFIER_CAPTURE_FILES = ("app/core/intelligence.py", "app/core/telemetry.py")


def _canonical(value: Any) -> str:
    """Serialize values deterministically for corpus fingerprinting."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _classifier_capture_fingerprint(project_root: Path) -> str:
    """Fingerprint current classifier sources without claiming persisted provenance."""
    digest = hashlib.sha256()
    for relative_path in CLASSIFIER_CAPTURE_FILES:
        digest.update(relative_path.encode("utf-8"))
        digest.update(b"\0")
        digest.update((project_root / relative_path).read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _iso(value: Any, fallback: datetime) -> str:
    """Normalize a timestamp to ISO format or use the snapshot fallback."""
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    text = str(value or "")
    return text or fallback.isoformat()


def _rule_evidence(item: dict[str, Any], observed_at: str) -> dict[str, Any]:
    """Convert one persisted rule detection into unified evidence."""
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
    """Collect deduplicated rule, rare-path, and persisted anomaly evidence."""
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
    """Derive reproducible corpus-selection reasons from state and evidence."""
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


def _rank_candidates(rows: Iterable[dict[str, Any]], ai_scores: dict[str, dict[str, Any]],
                     snapshot_at: datetime, high_volume_threshold: int) -> list[tuple]:
    """Build and sort candidate records by reason count and stable IP order."""
    candidates = []
    for row in rows:
        ip = str(row.get("identity_ip") or row.get("ip") or "")
        if not ip:
            continue
        evidence = _evidence(row, ai_scores.get(ip), snapshot_at)
        reasons = _reasons(row, evidence, high_volume_threshold)
        candidates.append((len(reasons), ip, row, evidence, reasons))
    candidates.sort(key=lambda item: (-item[0], item[1]))
    return candidates


def _case_packet(ip: str, row: dict[str, Any], evidence: list[dict[str, Any]],
                 traffic_for_ip: Callable, start: datetime, end: datetime) -> dict[str, Any]:
    """Build one bounded CasePacket from classification, traffic, and evidence."""
    traffic = traffic_for_ip(start, end, 3600, ip, settings.DATASET_LIVE_ID)
    total = int(traffic.get("total_requests") or 0)
    statuses = traffic.get("status_codes") or {}
    return build_case_packet(
        ip=ip,
        classification={"label": row.get("label") or "unknown", "risk_score": row.get("classification_score") or 0, "confidence": row.get("classification_confidence") or 0},
        window={"start": start.isoformat(), "end": end.isoformat()},
        traffic_summary={"requests": total, "unique_paths": len(traffic.get("top_paths") or []), "status_4xx_ratio": round(int(statuses.get("4xx") or 0) / total, 4) if total else 0},
        evidence=evidence,
        representative_requests=traffic.get("recent_requests") or [],
    )


def _score_comparison_snapshot(
    ip: str,
    row: dict[str, Any],
    packet: dict[str, Any],
    captured_at: datetime,
    classifier_capture_fingerprint: str | None,
) -> dict[str, Any]:
    """Capture selected persisted V1 inputs beside, not inside, the AI packet."""
    observation = row.get("observation_payload") or {}
    if not isinstance(observation, dict):
        observation = {}
    selected_present = "detections_recent" in observation
    selected_detections = observation.get("detections_recent")
    selected_valid = selected_present and isinstance(selected_detections, list)
    network_flags = {
        name: row.get(name) for name in ("is_tor", "is_proxy", "is_vpn", "is_hosting")
    }
    behavior_score = observation.get("recent_behavior_score")
    organization = row.get("organization")
    organization_confidence = row.get("organization_confidence")
    reconstructed_provenance = classification_input_provenance(
        row, observation, {}, None
    )
    return {
        "case_id": packet.get("case_id"),
        "ip": ip,
        "snapshot_at": packet.get("window", {}).get("end"),
        "captured_at": captured_at.isoformat(),
        "persisted_v1": {
            "label": row.get("label"),
            "score": row.get("classification_score"),
            "confidence": row.get("classification_confidence"),
            "input_contract_version": row.get("persisted_input_contract_version"),
            "input_fingerprint": row.get("persisted_input_fingerprint"),
            "classifier_version": None,
            "classifier_version_status": "not_stored_by_classification_persistence",
        },
        "input_fingerprint_reconstruction": {
            "contract_version": reconstructed_provenance["version"],
            "fingerprint": reconstructed_provenance["fingerprint"],
            "canonical_inputs": reconstructed_provenance["canonical_inputs"],
        },
        "behavior": {
            "selection_source": "observation_payload.detections_recent",
            "selected_detections_available": selected_valid,
            "selected_detections": selected_detections if selected_valid else None,
            "selected_detections_missing_reason": None if selected_valid else "detections_recent_not_persisted",
            "score": behavior_score,
            "requests": observation.get("recent_requests"),
            "sensitive_probe_requests": observation.get("recent_sensitive_probe_requests"),
            "evidence": observation.get("recent_behavior_evidence"),
            "evaluated_at": observation.get("evaluated_at"),
            "ruleset_hash": observation.get("ruleset_hash"),
            "ruleset_hash_1h": observation.get("ruleset_hash_1h"),
            "ruleset_hash_24h": observation.get("ruleset_hash_24h"),
        },
        "network_context": network_flags,
        "trust_reduction": {
            "organization": organization,
            "organization_confidence": organization_confidence,
            "is_hosting": row.get("is_hosting"),
            "behavior_score": behavior_score,
        },
        "scorer_provenance": {
            "persisted_classifier_version": None,
            "persisted_classifier_version_status": "not_stored_by_classification_persistence",
            "capture_classifier_fingerprint": classifier_capture_fingerprint,
            "capture_fingerprint_files": list(CLASSIFIER_CAPTURE_FILES),
            "ruleset_hash": observation.get("ruleset_hash"),
            "ruleset_hash_1h": observation.get("ruleset_hash_1h"),
            "ruleset_hash_24h": observation.get("ruleset_hash_24h"),
        },
    }


def _manifest(cases: list[dict[str, Any]], selection: dict[str, list[str]],
              score_comparison_snapshots: dict[str, dict[str, Any]],
              start: datetime, end: datetime) -> dict[str, Any]:
    """Create the corpus provenance envelope and canonical content hash."""
    corpus_hash = hashlib.sha256(_canonical(cases).encode("utf-8")).hexdigest()
    return {
        "manifest": {
            "corpus_created_at": end.isoformat(),
            "source_window": {"start": start.isoformat(), "end": end.isoformat()},
            "corpus_sha256": corpus_hash,
            "score_comparison_sha256": hashlib.sha256(_canonical(score_comparison_snapshots).encode("utf-8")).hexdigest(),
            "builder_version": BUILDER_VERSION,
            "packet_count": len(cases),
            "selection_reason": selection,
        },
        "cases": cases,
        "score_comparison_snapshots": score_comparison_snapshots,
    }


def build_corpus(
    rows: Iterable[dict[str, Any]],
    traffic_for_ip: Callable[[datetime, datetime, int, str, str], dict[str, Any]],
    snapshot_at: datetime,
    ai_scores: dict[str, dict[str, Any]] | None = None,
    limit: int = DEFAULT_LIMIT,
    high_volume_threshold: int = 1000,
    classifier_capture_fingerprint: str | None = None,
) -> dict[str, Any]:
    """Build deterministic packets from one PG snapshot and bounded CH reads."""
    end = snapshot_at.astimezone(timezone.utc)
    start = end - timedelta(hours=24)
    candidates = _rank_candidates(rows, ai_scores or {}, end, high_volume_threshold)
    selected = candidates[: max(1, min(int(limit), 30))]
    cases = []
    score_comparison_snapshots = {}
    selection = {}
    for _, ip, row, evidence, reasons in selected:
        packet = _case_packet(ip, row, evidence, traffic_for_ip, start, end)
        cases.append(packet)
        score_comparison_snapshots[str(packet["case_id"])] = _score_comparison_snapshot(
            ip, row, packet, end, classifier_capture_fingerprint
        )
        selection[ip] = reasons
    return _manifest(cases, selection, score_comparison_snapshots, start, end)


def main() -> int:
    """Load live read models, build the corpus, and write its local artifact."""
    parser = argparse.ArgumentParser(description="Build an untracked real CasePacket corpus")
    parser.add_argument("--output", type=Path, default=Path("data/ai/corpora/foundation-sec-real.json"))
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    parser.add_argument("--high-volume-threshold", type=int, default=1000)
    args = parser.parse_args()
    snapshot_at = datetime.now(timezone.utc)
    result = StateRepository().page(
        1, 5000, "threat_signal_score", "desc",
        include_classification_provenance=True,
    )
    rows = result["rows"]
    scores = {str(item["ip"]): item for item in AiRepository().scores([str(row.get("identity_ip") or row.get("ip")) for row in rows if row.get("identity_ip") or row.get("ip")])}
    classifier_fingerprint = _classifier_capture_fingerprint(Path(__file__).resolve().parents[2])
    corpus = build_corpus(
        rows, clickhouse.traffic_for_ip, snapshot_at, scores, args.limit,
        args.high_volume_threshold, classifier_fingerprint,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(corpus, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(corpus["manifest"], indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
