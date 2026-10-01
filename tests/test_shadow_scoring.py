from app.core import shadow_scoring
from app.core.rules import load_rules


def _evidence(identifier, points, *, source="rule", evidence_id=None):
    return {
        "source": source,
        "observed": {"rule_id": identifier} if source == "rule" else {},
        "evidence_id": evidence_id or f"ev-{identifier}",
        "score_contribution": points,
    }


def test_family_map_covers_all_seven_current_rules_and_groups_correlated_pairs():
    current_rule_ids = {rule.id for rule in load_rules()[0]}
    mapped_rule_ids = {key for key in shadow_scoring.FAMILY_MAP if key.startswith("WEB-")}

    assert len(current_rule_ids) == 7
    assert mapped_rule_ids == current_rule_ids
    assert shadow_scoring.FAMILY_RULES["traffic_rate"] == ("WEB-RATE-001", "WEB-BURST-001")
    assert shadow_scoring.FAMILY_RULES["http_error_activity"] == ("WEB-4XX-001", "WEB-BOT-001")
    assert shadow_scoring.FAMILY_RULES["reconnaissance"] == ("WEB-SCAN-001", "WEB-SENSITIVE-001")
    assert shadow_scoring.FAMILY_RULES["credential_attack"] == ("WEB-BRUTE-001",)
    assert shadow_scoring.POSSIBLE_CROSS_FAMILY_CORRELATIONS == (
        ("credential_attack", "traffic_rate"),
        ("credential_attack", "http_error_activity"),
    )


def test_firehol_abuseipdb_windows_share_one_reputation_family():
    result = shadow_scoring.score_shadow([
        _evidence("abuseipdb_1d", 0, source="firehol:abuseipdb_1d"),
        _evidence("abuseipdb_30d", 0, source="firehol:abuseipdb_30d"),
    ])

    assert result["family_scores"]["abuse_reputation"] == 0
    assert result["final_score"] == 0
    assert not result["correlation_adjustments"]
    assert all(row["family"] == "abuse_reputation" for row in result["raw_evidence"])


def test_correlated_behavior_rules_keep_raw_evidence_but_use_max_family_score():
    result = shadow_scoring.score_shadow([
        _evidence("WEB-RATE-001", 10),
        _evidence("WEB-BURST-001", 20),
        _evidence("WEB-4XX-001", 15),
        _evidence("WEB-BOT-001", 10),
        _evidence("WEB-BRUTE-001", 30),
    ])

    assert result["family_scores"] == {
        "traffic_rate": 20,
        "http_error_activity": 15,
        "reconnaissance": 0,
        "credential_attack": 30,
        "abuse_reputation": 0,
    }
    assert result["raw_family_total"] == result["final_score"] == 65
    assert [item["removed_points"] for item in result["correlation_adjustments"]] == [10, 10]
    assert len(result["raw_evidence"]) == 5


def test_correlation_adjustment_identifiers_use_unified_evidence_shape():
    result = shadow_scoring.score_shadow([
        {
            "source": "rule",
            "observed": {"rule_id": "WEB-RATE-001"},
            "score_contribution": 10,
        },
        {
            "source": "rule",
            "observed": {"rule_id": "WEB-BURST-001"},
            "score_contribution": 20,
        },
    ])

    assert result["correlation_adjustments"][0]["evidence_ids"] == [
        "WEB-RATE-001",
        "WEB-BURST-001",
    ]


def test_missing_coverage_is_distinct_from_available_family_with_no_match():
    result = shadow_scoring.score_shadow(
        [_evidence("WEB-RATE-001", 0)],
        available_families={"traffic_rate", "http_error_activity"},
    )

    assert result["family_scores"]["traffic_rate"] == 0
    assert result["missing_evidence"] == [
        {"family": "reconnaissance", "reason": "source_coverage_not_confirmed"},
        {"family": "credential_attack", "reason": "source_coverage_not_confirmed"},
        {"family": "abuse_reputation", "reason": "source_coverage_not_confirmed"},
    ]


def test_unmapped_evidence_is_preserved_but_not_scored_and_total_is_clamped():
    result = shadow_scoring.score_shadow([
        _evidence("WEB-RATE-001", 10),
        _evidence("WEB-BURST-001", 20),
        _evidence("WEB-4XX-001", 15),
        _evidence("WEB-BOT-001", 10),
        _evidence("WEB-SCAN-001", 15),
        _evidence("WEB-SENSITIVE-001", 50),
        _evidence("WEB-BRUTE-001", 30),
        _evidence("some-provider", 50, source="other-provider"),
    ])

    assert result["raw_family_total"] == 115
    assert result["final_score"] == 100
    assert result["correlation_adjustments"][-1]["method"] == "final_score_clamp"
    assert result["unmapped_evidence"] == [result["raw_evidence"][-1]]
    assert result["raw_evidence"][-1]["score_contribution"] == 50


def test_shadow_scorer_rejects_invalid_points():
    try:
        shadow_scoring.score_shadow([_evidence("WEB-RATE-001", True)])
    except ValueError as exc:
        assert "integer" in str(exc)
    else:
        raise AssertionError("invalid boolean contribution should be rejected")
