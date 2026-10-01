import json

from app.core.shadow_backtest import build_backtest_report
from scripts.ops import shadow_backtest


def _packet(case_id, ip, v1_score, evidence, *, end="2026-09-03T03:30:34+00:00"):
    return {
        "case_id": case_id,
        "evidence_fingerprint": f"fp-{case_id}",
        "subject": {"ip": ip},
        "classification": {"label": "medium", "risk_score": v1_score},
        "window": {"start": "2026-09-02T03:30:34+00:00", "end": end},
        "evidence": evidence,
    }


def _evidence(rule_id, points, *, evidence_id=None):
    return {
        "evidence_id": evidence_id or f"ev-{rule_id}",
        "source": "rule",
        "type": "rule",
        "observed": {"rule_id": rule_id},
        "score_contribution": points,
    }


def _corpus(name, cases, *, builder_version="casebuilder-v1", available=None, snapshots=None):
    manifest = {
        "builder_version": builder_version,
        "corpus_sha256": f"corpus-{name}",
        "corpus_created_at": "2026-09-03T03:30:34+00:00",
    }
    if available is not None:
        for packet in cases:
            packet["available_evidence_families"] = available
    return {
        "source_file": f"{name}.json", "source_sha256": f"sha-{name}",
        "manifest": manifest, "cases": cases,
        "score_comparison_snapshots": snapshots or {},
    }


def test_report_compares_persisted_v1_and_shadow_with_provenance_and_breakdown():
    first = _packet("case-a", "203.0.113.10", 30, [
        _evidence("WEB-RATE-001", 10),
        _evidence("WEB-BURST-001", 15),
        {"evidence_id": "ev-other", "source": "provider-x", "type": "reputation", "score_contribution": 7},
    ])
    second = _packet("case-b", "2001:db8::1", 15, [_evidence("WEB-RATE-001", 15)])
    missing_score = _packet("case-no-score", "203.0.113.11", 0, [])
    del missing_score["classification"]["risk_score"]
    invalid_score = _packet("case-bad-score", "203.0.113.12", 101, [])
    missing_evidence = _packet("case-no-evidence", "203.0.113.13", 0, [])
    del missing_evidence["evidence"]
    corpus = _corpus("selected", [first, second, missing_score, invalid_score, missing_evidence])

    report = build_backtest_report([corpus])

    assert report["cohort_size"] == 5
    assert report["usable_cases"] == 2
    assert report["skipped_cases"] == 3
    assert report["skipped_reasons"] == {
        "invalid_persisted_v1_score": 1,
        "missing_evidence_array": 1,
        "missing_persisted_v1_score": 1,
    }
    assert report["score_summaries"] == {
        "v1": {"count": 2, "mean": 22.5, "median": 22.5, "min": 15, "max": 30},
        "shadow": {"count": 2, "mean": 15, "median": 15.0, "min": 15, "max": 15},
    }
    assert report["delta_distribution"] == {"count": 2, "mean": -7.5, "median": -7.5, "min": -15, "max": 0}
    assert report["exact_agreement_count"] == 1
    assert report["disagreement_count"] == 1
    case = report["disagreement_cases"][0]
    assert case["provenance"]["case_id"] == "case-a"
    assert case["provenance"]["ip"] == "203.0.113.10"
    assert case["provenance"]["snapshot_at"] == "2026-09-03T03:30:34+00:00"
    assert case["provenance"]["corpus_builder_version"] == "casebuilder-v1"
    assert case["v1_score_provenance"] == {
        "mode": "persisted_snapshot",
        "field": "classification.risk_score",
        "version": None,
        "version_status": "not_recorded_in_packet",
        "corpus_builder_version": "casebuilder-v1",
    }
    assert case["evidence_breakdown"]["family_scores"]["traffic_rate"] == 15
    assert case["evidence_breakdown"]["correlation_adjustments"][0]["removed_points"] == 10
    assert case["evidence_breakdown"]["unmapped_evidence"][0]["evidence_id"] == "ev-other"
    assert report["correlation_points_removed"] == {
        "by_family": {"traffic_rate": 10},
        "same_family_total": 10,
        "final_clamp_total": 0,
    }
    assert report["unmapped_evidence"] == {
        "count": 1,
        "score_contribution_total": 7,
        "by_source_type": {"provider-x:reputation": 1},
    }
    assert report["cohort"]["population_representative"] is False
    assert report["shadow_label_inferred"] is False
    assert report["comparability"] == {
        "paired_snapshot_scores": True,
        "v1_recomputed": False,
        "v1_full_input_reconstructable": False,
        "shadow_input_coverage": "partial_or_unknown",
        "delta_attributable_to_family_dedup_only": False,
        "future_v1_input_capture": {
            "cases_with_sidecar": 0,
            "cases_without_sidecar": 2,
            "selected_behavior_available": 0,
            "network_context_fields_captured": 0,
            "trust_reduction_fields_captured": 0,
            "persisted_classifier_version_recorded": 0,
            "ruleset_hash_recorded": 0,
            "cases": 2,
            "selected_behavior_available_percent": 0.0,
            "network_context_fields_captured_percent": 0.0,
            "trust_reduction_fields_captured_percent": 0.0,
            "persisted_classifier_version_recorded_percent": 0.0,
            "ruleset_hash_recorded_percent": 0.0,
        },
        "v1_input_fingerprint_alignment": {
            "counts": {"missing_sidecar": 2},
            "all_usable_cases_matched": False,
        },
        "limitations": [
            "Shadow scoring still consumes CasePacket evidence only; the sidecar is reported for adequacy and is not yet applied to the candidate formula.",
            "Persisted classifier version is not stored, so captured current source fingerprint cannot prove which code produced the saved V1 score.",
            "Input fingerprint matches show captured canonical inputs agree with provenance stored beside the V1 score; they do not identify the historical classifier implementation.",
        ],
    }


def test_report_joins_comparison_sidecar_and_reports_input_adequacy():
    packet = _packet("case-sidecar", "203.0.113.15", 20, [_evidence("WEB-RATE-001", 10)])
    snapshot = {
        "case_id": "case-sidecar",
        "ip": "203.0.113.15",
        "behavior": {"selected_detections_available": True, "selected_detections": [{"id": "WEB-RATE-001"}]},
        "network_context": {"is_tor": False, "is_proxy": False, "is_vpn": False, "is_hosting": True},
        "trust_reduction": {"organization": "Example", "organization_confidence": 90, "is_hosting": True, "behavior_score": 10},
        "scorer_provenance": {"persisted_classifier_version": None, "ruleset_hash": "rules-v1"},
    }
    report = build_backtest_report([_corpus("sidecar", [packet], snapshots={"case-sidecar": snapshot})])

    assert report["comparability"]["delta_attributable_to_family_dedup_only"] is False
    assert report["comparability"]["future_v1_input_capture"] == {
        "cases_with_sidecar": 1,
        "cases_without_sidecar": 0,
        "selected_behavior_available": 1,
        "network_context_fields_captured": 1,
        "trust_reduction_fields_captured": 1,
        "persisted_classifier_version_recorded": 0,
        "ruleset_hash_recorded": 1,
        "cases": 1,
        "selected_behavior_available_percent": 100.0,
        "network_context_fields_captured_percent": 100.0,
        "trust_reduction_fields_captured_percent": 100.0,
        "persisted_classifier_version_recorded_percent": 0.0,
        "ruleset_hash_recorded_percent": 100.0,
    }
    assert report["disagreement_cases"][0]["v1_input_snapshot"] == snapshot


def test_report_checks_reconstructed_input_fingerprints_and_keeps_legacy_cases_unknown():
    cases = [
        _packet("matched", "203.0.113.51", 20, [_evidence("WEB-RATE-001", 10)]),
        _packet("mismatch", "203.0.113.52", 20, [_evidence("WEB-RATE-001", 10)]),
        _packet("old-sidecar", "203.0.113.53", 20, [_evidence("WEB-RATE-001", 10)]),
        _packet("old-corpus", "203.0.113.54", 20, [_evidence("WEB-RATE-001", 10)]),
    ]
    snapshots = {
        "matched": {
            "persisted_v1": {
                "input_contract_version": "classification-input-v1",
                "input_fingerprint": "digest-a",
            },
            "input_fingerprint_reconstruction": {
                "contract_version": "classification-input-v1",
                "fingerprint": "digest-a",
                "canonical_inputs": {"observation": {"behavior_score": 10}},
            },
        },
        "mismatch": {
            "persisted_v1": {
                "input_contract_version": "classification-input-v1",
                "input_fingerprint": "digest-b",
            },
            "input_fingerprint_reconstruction": {
                "contract_version": "classification-input-v1",
                "fingerprint": "digest-c",
                "canonical_inputs": {"observation": {"behavior_score": 11}},
            },
        },
        "old-sidecar": {"persisted_v1": {"score": 20}},
    }

    report = build_backtest_report([_corpus("alignment", cases, snapshots=snapshots)])

    assert report["input_fingerprint_alignment"]["counts"] == {
        "matched": 1,
        "mismatch": 1,
        "missing_persisted_provenance": 1,
        "missing_sidecar": 1,
    }
    by_case = {item["case_id"]: item for item in report["input_fingerprint_alignment"]["cases"]}
    assert by_case["matched"]["status"] == "matched"
    assert by_case["matched"]["persisted_fingerprint"] == "digest-a"
    assert by_case["mismatch"]["status"] == "mismatch"
    assert by_case["old-sidecar"]["status"] == "missing_persisted_provenance"
    assert by_case["old-corpus"]["status"] == "missing_sidecar"
    assert report["comparability"]["v1_input_fingerprint_alignment"] == {
        "counts": report["input_fingerprint_alignment"]["counts"],
        "all_usable_cases_matched": False,
    }


def test_snapshot_time_uses_packet_window_and_keeps_corpus_created_time_separate():
    packet = _packet(
        "case-time",
        "203.0.113.21",
        12,
        [_evidence("WEB-RATE-001", 10)],
        end="2026-09-03T08:00:00+00:00",
    )
    corpus = _corpus("time", [packet])
    corpus["manifest"]["corpus_created_at"] = "2026-09-03T09:00:00+00:00"

    report = build_backtest_report([corpus])

    provenance = report["disagreement_cases"][0]["provenance"]
    assert provenance["snapshot_at"] == "2026-09-03T08:00:00+00:00"
    assert provenance["snapshot_source"] == "packet.window.end"
    assert provenance["corpus_created_at"] == "2026-09-03T09:00:00+00:00"


def test_declared_family_coverage_distinguishes_missing_from_zero_signal():
    packet = _packet("case-zero", "203.0.113.20", 0, [])
    corpus = _corpus("coverage", [packet], available=["traffic_rate", "http_error_activity"])

    report = build_backtest_report([corpus])

    assert report["family_coverage"]["traffic_rate"] == {
        "with_evidence": 0,
        "declared_available": 1,
        "coverage_unknown": 0,
        "cases": 1,
        "evidence_coverage_percent": 100.0,
    }
    assert report["family_coverage"]["reconnaissance"]["evidence_coverage_percent"] == 0.0
    assert report["missing_evidence"]["unconfirmed_family_cases"]["reconnaissance"] == 1


def test_report_is_deterministic_when_input_corpus_order_changes():
    alpha = _corpus("alpha", [_packet("case-z", "203.0.113.30", 20, [_evidence("WEB-RATE-001", 10)])])
    beta = _corpus("beta", [_packet("case-a", "203.0.113.31", 5, [_evidence("WEB-BRUTE-001", 5)])])

    assert build_backtest_report([alpha, beta]) == build_backtest_report([beta, alpha])


def test_cli_reads_saved_corpus_and_prints_deterministic_json(tmp_path, monkeypatch, capsys):
    packet = _packet("case-cli", "203.0.113.40", 12, [_evidence("WEB-RATE-001", 8)])
    path = tmp_path / "corpus.json"
    path.write_text(json.dumps({"manifest": {"builder_version": "fixture-v1"}, "cases": [packet]}))
    original = path.read_bytes()

    monkeypatch.setattr("sys.argv", ["shadow_backtest", str(path)])
    assert shadow_backtest.main() == 0
    first_output = capsys.readouterr().out
    assert shadow_backtest.main() == 0
    second_output = capsys.readouterr().out

    assert first_output == second_output
    report = json.loads(first_output)
    assert report["usable_cases"] == 1
    assert report["input_corpora"][0]["builder_version"] == "fixture-v1"
    assert report["comparability"]["future_v1_input_capture"]["cases_without_sidecar"] == 1
    assert path.read_bytes() == original
    assert "shadow_label" not in report and report["shadow_label_inferred"] is False


def test_loader_reports_invalid_json_without_creating_or_changing_files(tmp_path):
    path = tmp_path / "invalid.json"
    path.write_text("not json")
    original = path.read_bytes()

    loaded = shadow_backtest._load_corpus(path)
    report = build_backtest_report([loaded])

    assert report["input_errors"] == [{"source_file": "invalid.json", "reason": "invalid_json"}]
    assert report["cohort_size"] == report["usable_cases"] == report["skipped_cases"] == 0
    assert path.read_bytes() == original


def test_loader_preserves_score_comparison_sidecar(tmp_path):
    packet = _packet("case-load", "203.0.113.41", 12, [_evidence("WEB-RATE-001", 8)])
    sidecar = {"case-load": {"case_id": "case-load", "scorer_provenance": {"ruleset_hash": "r1"}}}
    path = tmp_path / "corpus.json"
    path.write_text(json.dumps({"manifest": {}, "cases": [packet], "score_comparison_snapshots": sidecar}))

    loaded = shadow_backtest._load_corpus(path)
    report = build_backtest_report([loaded])

    assert loaded["score_comparison_snapshots"] == sidecar
    assert report["disagreement_cases"][0]["v1_input_snapshot"] == sidecar["case-load"]
