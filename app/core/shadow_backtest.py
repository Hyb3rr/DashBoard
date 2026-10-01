"""Pure comparison and reporting for saved CasePacket shadow backtests."""

from __future__ import annotations

import ipaddress
import statistics
from collections import Counter
from collections.abc import Iterable, Mapping
from typing import Any

from app.core.shadow_scoring import FAMILY_RULES, score_shadow


REPORT_VERSION = "shadow-backtest-v2"


def _valid_score(value: Any) -> int | None:
    """Return an in-range persisted score, rejecting booleans and coercions."""
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 100:
        return None
    return value


def _packet_context(packet: Mapping[str, Any], corpus: Mapping[str, Any]) -> dict[str, Any]:
    """Project stable source and snapshot identity for one packet."""
    manifest = corpus.get("manifest") if isinstance(corpus.get("manifest"), Mapping) else {}
    subject = packet.get("subject") if isinstance(packet.get("subject"), Mapping) else {}
    window = packet.get("window") if isinstance(packet.get("window"), Mapping) else {}
    classification = packet.get("classification") if isinstance(packet.get("classification"), Mapping) else {}
    ip = str(subject.get("ip") or "")
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        pass
    snapshot_at = window.get("end") or ""
    score_version = (
        classification.get("score_version")
        or manifest.get("scoring_version")
        or manifest.get("classification_version")
    )
    return {
        "case_id": packet.get("case_id"),
        "evidence_fingerprint": packet.get("evidence_fingerprint"),
        "ip": ip or None,
        "snapshot_at": snapshot_at or None,
        "snapshot_source": "packet.window.end" if snapshot_at else None,
        "corpus_created_at": manifest.get("corpus_created_at"),
        "corpus_builder_version": manifest.get("builder_version"),
        "persisted_score_version": score_version,
        "persisted_v1_score_field": "classification.risk_score",
    }


def _skip_reason(packet: Any) -> str | None:
    """Return the first deterministic reason a packet cannot be compared."""
    if not isinstance(packet, Mapping):
        return "case_not_object"
    subject = packet.get("subject")
    if not isinstance(subject, Mapping) or not subject.get("ip"):
        return "missing_subject_ip"
    classification = packet.get("classification")
    if not isinstance(classification, Mapping):
        return "missing_classification"
    if "risk_score" not in classification:
        return "missing_persisted_v1_score"
    if _valid_score(classification.get("risk_score")) is None:
        return "invalid_persisted_v1_score"
    if not isinstance(packet.get("evidence"), list):
        return "missing_evidence_array"
    return None


def _summarize(values: list[int]) -> dict[str, int | float | None]:
    """Summarize an integer score series with deterministic basic statistics."""
    if not values:
        return {"count": 0, "mean": None, "median": None, "min": None, "max": None}
    return {
        "count": len(values),
        "mean": round(statistics.fmean(values), 4),
        "median": statistics.median(values),
        "min": min(values),
        "max": max(values),
    }


def _evidence_breakdown(scored: Mapping[str, Any]) -> dict[str, Any]:
    """Keep compact evidence and family explanations for a disagreement."""
    def evidence_key(item: Mapping[str, Any]) -> Any:
        observed = item.get("observed")
        rule_id = observed.get("rule_id") if isinstance(observed, Mapping) else None
        return item.get("evidence_id") or rule_id or item.get("source")

    return {
        "family_scores": scored["family_scores"],
        "evidence": [
            {
                "evidence_id": item.get("evidence_id"),
                "evidence_key": evidence_key(item),
                "source": item.get("source"),
                "type": item.get("type"),
                "family": item.get("family"),
                "score_contribution": item.get("score_contribution"),
            }
            for item in scored["raw_evidence"]
        ],
        "missing_evidence": scored["missing_evidence"],
        "unmapped_evidence": [
            {
                "evidence_id": item.get("evidence_id"),
                "source": item.get("source"),
                "type": item.get("type"),
                "score_contribution": item.get("score_contribution"),
            }
            for item in scored["unmapped_evidence"]
        ],
        "correlation_adjustments": scored["correlation_adjustments"],
    }


def _input_fingerprint_alignment(sidecar: Mapping[str, Any] | None) -> dict[str, Any]:
    """Compare a captured canonical-input digest with persisted V1 provenance."""
    if sidecar is None:
        return {"status": "missing_sidecar", "persisted_contract_version": None,
                "persisted_fingerprint": None, "reconstructed_contract_version": None,
                "reconstructed_fingerprint": None}
    persisted = sidecar.get("persisted_v1") if isinstance(sidecar.get("persisted_v1"), Mapping) else {}
    reconstructed = sidecar.get("input_fingerprint_reconstruction")
    reconstructed = reconstructed if isinstance(reconstructed, Mapping) else {}
    persisted_version = persisted.get("input_contract_version")
    persisted_fingerprint = persisted.get("input_fingerprint")
    reconstructed_version = reconstructed.get("contract_version")
    reconstructed_fingerprint = reconstructed.get("fingerprint")
    if not persisted_version or not persisted_fingerprint:
        status = "missing_persisted_provenance"
    elif not reconstructed_version or not reconstructed_fingerprint:
        status = "missing_reconstructed_fingerprint"
    elif persisted_version != reconstructed_version:
        status = "contract_version_mismatch"
    elif persisted_fingerprint == reconstructed_fingerprint:
        status = "matched"
    else:
        status = "mismatch"
    return {
        "status": status,
        "persisted_contract_version": persisted_version,
        "persisted_fingerprint": persisted_fingerprint,
        "reconstructed_contract_version": reconstructed_version,
        "reconstructed_fingerprint": reconstructed_fingerprint,
    }


def _available_families(packet: Mapping[str, Any]) -> set[str]:
    """Read optional caller-declared evidence coverage without inferring it."""
    values = packet.get("available_evidence_families")
    if values is None:
        coverage = packet.get("evidence_coverage")
        values = coverage.get("available_families") if isinstance(coverage, Mapping) else None
    if values is None:
        return set()
    if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
        raise ValueError("available evidence families must be a list of strings")
    return set(values)


def build_backtest_report(corpora: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Compare saved V1 scores with shadow scores over one paired cohort."""
    normalized_corpora = sorted(
        (dict(item) for item in corpora),
        key=lambda item: (str(item.get("source_file") or ""), str(item.get("source_sha256") or "")),
    )
    cohort_size = 0
    usable = []
    skipped = []
    skipped_reasons: Counter[str] = Counter()
    input_errors = []
    family_coverage = {
        family: {"with_evidence": 0, "declared_available": 0, "coverage_unknown": 0}
        for family in FAMILY_RULES
    }
    total_correlation_removed = Counter()
    total_clamp_removed = 0
    missing_family_cases = Counter()
    unmapped_evidence_counts = Counter()
    unmapped_evidence_points = 0
    comparison_snapshot_coverage = Counter()
    input_alignment_counts = Counter()
    input_alignment_cases = []

    for corpus in normalized_corpora:
        if corpus.get("load_error"):
            input_errors.append({"source_file": corpus.get("source_file"), "reason": corpus["load_error"]})
            continue
        packets = corpus.get("cases")
        if not isinstance(packets, list):
            skipped.append({"source_file": corpus.get("source_file"), "reason": "missing_cases_array"})
            skipped_reasons["missing_cases_array"] += 1
            continue
        manifest = corpus.get("manifest") if isinstance(corpus.get("manifest"), Mapping) else {}
        sidecars = corpus.get("score_comparison_snapshots")
        if not isinstance(sidecars, Mapping):
            sidecars = {}
        source = {
            "source_file": corpus.get("source_file"),
            "source_sha256": corpus.get("source_sha256"),
            "corpus_sha256": manifest.get("corpus_sha256"),
            "score_comparison_sha256": manifest.get("score_comparison_sha256"),
            "builder_version": manifest.get("builder_version"),
            "source_window": manifest.get("source_window"),
        }
        indexed_packets = list(enumerate(packets))
        indexed_packets.sort(key=lambda item: (
            str((item[1].get("subject") or {}).get("ip", "")) if isinstance(item[1], Mapping) else "",
            str((item[1].get("window") or {}).get("end", "")) if isinstance(item[1], Mapping) else "",
            str(item[1].get("case_id", "")) if isinstance(item[1], Mapping) else "",
            item[0],
        ))
        for packet_index, packet in indexed_packets:
            cohort_size += 1
            context = _packet_context(packet, {**corpus, "manifest": manifest}) if isinstance(packet, Mapping) else {
                "case_id": None, "evidence_fingerprint": None, "ip": None, "snapshot_at": None,
                "snapshot_source": None, "corpus_created_at": manifest.get("corpus_created_at"),
                "corpus_builder_version": manifest.get("builder_version"),
                "persisted_score_version": None,
                "persisted_v1_score_field": "classification.risk_score",
            }
            provenance = {**source, "packet_index": packet_index, **context}
            reason = _skip_reason(packet)
            if reason:
                skipped.append({**provenance, "reason": reason})
                skipped_reasons[reason] += 1
                continue
            try:
                available = _available_families(packet)
                scored = score_shadow(packet["evidence"], available_families=available)
            except (TypeError, ValueError) as exc:
                reason = "invalid_evidence"
                if "unknown evidence families" in str(exc):
                    reason = "unknown_evidence_family"
                skipped.append({**provenance, "reason": reason})
                skipped_reasons[reason] += 1
                continue

            classification = packet["classification"]
            case_id = packet.get("case_id")
            sidecar = sidecars.get(str(case_id)) if case_id is not None else None
            if not isinstance(sidecar, Mapping):
                sidecar = None
            input_alignment = _input_fingerprint_alignment(sidecar)
            input_alignment_counts[input_alignment["status"]] += 1
            input_alignment_cases.append({
                "case_id": case_id,
                "ip": context["ip"],
                "snapshot_at": context["snapshot_at"],
                **input_alignment,
            })
            comparison_snapshot_coverage["cases_with_sidecar" if sidecar else "cases_without_sidecar"] += 1
            behavior_snapshot = sidecar.get("behavior") if sidecar and isinstance(sidecar.get("behavior"), Mapping) else {}
            network_snapshot = sidecar.get("network_context") if sidecar and isinstance(sidecar.get("network_context"), Mapping) else {}
            trust_snapshot = sidecar.get("trust_reduction") if sidecar and isinstance(sidecar.get("trust_reduction"), Mapping) else {}
            scorer_snapshot = sidecar.get("scorer_provenance") if sidecar and isinstance(sidecar.get("scorer_provenance"), Mapping) else {}
            comparison_snapshot_coverage["selected_behavior_available"] += int(
                behavior_snapshot.get("selected_detections_available") is True
            )
            comparison_snapshot_coverage["network_context_fields_captured"] += int(
                all(key in network_snapshot for key in ("is_tor", "is_proxy", "is_vpn", "is_hosting"))
            )
            comparison_snapshot_coverage["trust_reduction_fields_captured"] += int(
                all(key in trust_snapshot for key in ("organization", "organization_confidence", "is_hosting", "behavior_score"))
            )
            comparison_snapshot_coverage["persisted_classifier_version_recorded"] += int(
                bool(scorer_snapshot.get("persisted_classifier_version"))
            )
            comparison_snapshot_coverage["ruleset_hash_recorded"] += int(bool(scorer_snapshot.get("ruleset_hash")))
            v1_score = classification["risk_score"]
            shadow_score = scored["final_score"]
            delta = shadow_score - v1_score
            evidence_families = {item.get("family") for item in scored["raw_evidence"] if item.get("family")}
            for item in scored["missing_evidence"]:
                missing_family_cases[item["family"]] += 1
            for item in scored["unmapped_evidence"]:
                source_type = f"{item.get('source') or 'unknown'}:{item.get('type') or 'unknown'}"
                unmapped_evidence_counts[source_type] += 1
                unmapped_evidence_points += item["score_contribution"]
            for family in FAMILY_RULES:
                if family in evidence_families:
                    family_coverage[family]["with_evidence"] += 1
                elif family in available:
                    family_coverage[family]["declared_available"] += 1
                else:
                    family_coverage[family]["coverage_unknown"] += 1
            for adjustment in scored["correlation_adjustments"]:
                if adjustment["method"] == "maximum_within_correlated_family":
                    total_correlation_removed[adjustment["family"]] += adjustment["removed_points"]
                elif adjustment["method"] == "final_score_clamp":
                    total_clamp_removed += adjustment["removed_points"]

            usable.append({
                "provenance": provenance,
                "v1_score": v1_score,
                "v1_score_provenance": {
                    "mode": "persisted_snapshot",
                    "field": "classification.risk_score",
                    "version": context["persisted_score_version"],
                    "version_status": "recorded" if context["persisted_score_version"] else "not_recorded_in_packet",
                    "corpus_builder_version": context["corpus_builder_version"],
                },
                "shadow_score": shadow_score,
                "delta_shadow_minus_v1": delta,
                "v1_input_snapshot": dict(sidecar) if sidecar else None,
                "input_fingerprint_alignment": input_alignment,
                "evidence_breakdown": _evidence_breakdown(scored),
            })

    usable.sort(key=lambda item: (
        str(item["provenance"].get("source_file") or ""),
        str(item["provenance"].get("ip") or ""),
        str(item["provenance"].get("snapshot_at") or ""),
        str(item["provenance"].get("case_id") or ""),
        item["provenance"].get("packet_index", -1),
    ))
    v1_scores = [item["v1_score"] for item in usable]
    shadow_scores = [item["shadow_score"] for item in usable]
    deltas = [item["delta_shadow_minus_v1"] for item in usable]
    disagreements = [item for item in usable if item["delta_shadow_minus_v1"] != 0]
    for family in family_coverage:
        family_coverage[family]["cases"] = len(usable)
        family_coverage[family]["evidence_coverage_percent"] = (
            round(100 * (family_coverage[family]["with_evidence"] + family_coverage[family]["declared_available"]) / len(usable), 2)
            if usable else None
        )

    snapshot_case_count = comparison_snapshot_coverage["cases_with_sidecar"] + comparison_snapshot_coverage["cases_without_sidecar"]
    input_alignment_cases.sort(key=lambda item: (
        str(item.get("ip") or ""), str(item.get("snapshot_at") or ""),
        str(item.get("case_id") or ""),
    ))
    input_capture = {
        "cases_with_sidecar": comparison_snapshot_coverage["cases_with_sidecar"],
        "cases_without_sidecar": comparison_snapshot_coverage["cases_without_sidecar"],
        "selected_behavior_available": comparison_snapshot_coverage["selected_behavior_available"],
        "network_context_fields_captured": comparison_snapshot_coverage["network_context_fields_captured"],
        "trust_reduction_fields_captured": comparison_snapshot_coverage["trust_reduction_fields_captured"],
        "persisted_classifier_version_recorded": comparison_snapshot_coverage["persisted_classifier_version_recorded"],
        "ruleset_hash_recorded": comparison_snapshot_coverage["ruleset_hash_recorded"],
        "cases": snapshot_case_count,
    }
    for field in (
        "selected_behavior_available", "network_context_fields_captured",
        "trust_reduction_fields_captured", "persisted_classifier_version_recorded",
        "ruleset_hash_recorded",
    ):
        input_capture[f"{field}_percent"] = round(
            100 * input_capture[field] / snapshot_case_count, 2
        ) if snapshot_case_count else None

    return {
        "report_version": REPORT_VERSION,
        "cohort": {
            "kind": "selected_casepacket_corpus",
            "population_representative": False,
            "description": "Selected CasePacket cases; this cohort does not represent the production IP population.",
        },
        "comparability": {
            "paired_snapshot_scores": True,
            "v1_recomputed": False,
            "v1_full_input_reconstructable": False,
            "shadow_input_coverage": "partial_or_unknown",
            "delta_attributable_to_family_dedup_only": False,
            "future_v1_input_capture": input_capture,
            "v1_input_fingerprint_alignment": {
                "counts": dict(sorted(input_alignment_counts.items())),
                "all_usable_cases_matched": bool(usable) and input_alignment_counts.get("matched", 0) == len(usable),
            },
            "limitations": [
                "Shadow scoring still consumes CasePacket evidence only; the sidecar is reported for adequacy and is not yet applied to the candidate formula.",
                "Persisted classifier version is not stored, so captured current source fingerprint cannot prove which code produced the saved V1 score.",
                "Input fingerprint matches show captured canonical inputs agree with provenance stored beside the V1 score; they do not identify the historical classifier implementation.",
            ],
        },
        "input_fingerprint_alignment": {
            "counts": dict(sorted(input_alignment_counts.items())),
            "cases": input_alignment_cases,
        },
        "input_corpora": [
            {
                "source_file": item.get("source_file"),
                "source_sha256": item.get("source_sha256"),
                "corpus_sha256": (item.get("manifest") or {}).get("corpus_sha256") if isinstance(item.get("manifest"), Mapping) else None,
                "score_comparison_sha256": (item.get("manifest") or {}).get("score_comparison_sha256") if isinstance(item.get("manifest"), Mapping) else None,
                "builder_version": (item.get("manifest") or {}).get("builder_version") if isinstance(item.get("manifest"), Mapping) else None,
                "source_window": (item.get("manifest") or {}).get("source_window") if isinstance(item.get("manifest"), Mapping) else None,
            }
            for item in normalized_corpora
        ],
        "cohort_size": cohort_size,
        "usable_cases": len(usable),
        "skipped_cases": len(skipped),
        "skipped_reasons": dict(sorted(skipped_reasons.items())),
        "skipped": skipped,
        "input_errors": input_errors,
        "v1_score_source": "persisted CasePacket classification.risk_score; no historical recomputation",
        "score_summaries": {"v1": _summarize(v1_scores), "shadow": _summarize(shadow_scores)},
        "delta_distribution": _summarize(deltas),
        "delta_definition": "shadow_score - persisted_v1_score",
        "exact_agreement_count": sum(delta == 0 for delta in deltas),
        "disagreement_count": len(disagreements),
        "disagreement_cases": disagreements,
        "family_coverage": family_coverage,
        "missing_evidence": {
            "unconfirmed_family_cases": dict(sorted(missing_family_cases.items())),
            "meaning": "No evidence or explicit available-family declaration was present in the packet; this is not an observed negative.",
        },
        "unmapped_evidence": {
            "count": sum(unmapped_evidence_counts.values()),
            "score_contribution_total": unmapped_evidence_points,
            "by_source_type": dict(sorted(unmapped_evidence_counts.items())),
        },
        "correlation_points_removed": {
            "by_family": dict(sorted(total_correlation_removed.items())),
            "same_family_total": sum(total_correlation_removed.values()),
            "final_clamp_total": total_clamp_removed,
        },
        "candidate_formula": "clamp(sum(max(score_contribution per evidence family)), 0, 100)",
        "shadow_label_inferred": False,
    }
