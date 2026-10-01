from app.core.classification_provenance import (
    CLASSIFICATION_INPUT_VERSION,
    classification_input_provenance,
)


def _inputs():
    return (
        {
            "is_tor": False,
            "is_proxy": False,
            "is_vpn": False,
            "is_hosting": False,
            "organization": "Example Network",
            "organization_confidence": 80,
            "country_code": "US",
            "core_enrichment_status": "complete",
            "privacy_enrichment_status": "complete",
            "fetched_at": "2026-09-01T00:00:00Z",
        },
        {
            "recent_behavior_score": 12,
            "recent_requests": 20,
            "recent_sensitive_probe_requests": 0,
            "recent_behavior_evidence": ["rate rule"],
            "rule_coverage": True,
            "evaluated_at": "2026-09-01T00:00:00Z",
            "detections_24h": [{"id": "unused-by-classifier"}],
        },
        {
            "country_name": "Exampleland",
            "conflict_indicators": [
                {"type": "elevated_tension", "severity": "medium", "value": "elevated geopolitical conflict"}
            ],
            "updated_at": "2026-09-01T00:00:00Z",
        },
        {
            "ai_anomaly_score": 72,
            "windows_seen": 3,
            "anomalous_windows": 2,
            "confidence": 80,
            "confidence_level": "high",
            "scored_at": "2026-09-01T00:00:00Z",
        },
    )


def test_provenance_returns_contract_version_canonical_inputs_and_fingerprint():
    result = classification_input_provenance(*_inputs())

    assert result["version"] == CLASSIFICATION_INPUT_VERSION == "classification-input-v2"
    assert len(result["fingerprint"]) == 64
    assert result["canonical_inputs"]["profile"]["is_proxy"] is False
    assert "fetched_at" not in result["canonical_inputs"]["profile"]
    assert "evaluated_at" not in result["canonical_inputs"]["observation"]
    assert "detections_24h" not in result["canonical_inputs"]["observation"]
    assert "updated_at" not in result["canonical_inputs"]["region_profile"]
    assert "scored_at" not in result["canonical_inputs"]["ai_profile"]


def test_unused_metadata_changes_do_not_change_fingerprint():
    profile, observation, region, ai = _inputs()
    first = classification_input_provenance(profile, observation, region, ai)
    changed = classification_input_provenance(
        {**profile, "fetched_at": "later"},
        {
            **observation,
            "evaluated_at": "later",
            "detections_24h": [{"id": "other"}],
            "behavior_score": 99,
            "requests": 999,
            "sensitive_probe_requests": 999,
        },
        {**region, "updated_at": "later"},
        {**ai, "scored_at": "later"},
    )

    assert changed["fingerprint"] == first["fingerprint"]


def test_consumed_input_changes_change_fingerprint():
    profile, observation, region, ai = _inputs()
    original = classification_input_provenance(profile, observation, region, ai)
    changed = classification_input_provenance(
        {**profile, "is_proxy": True}, observation, region, ai
    )

    assert changed["fingerprint"] != original["fingerprint"]


def test_selected_behavior_input_changes_change_fingerprint():
    profile, observation, region, ai = _inputs()
    original = classification_input_provenance(profile, observation, region, ai)
    changed = classification_input_provenance(
        profile, {**observation, "recent_behavior_score": 13}, region, ai
    )

    assert changed["fingerprint"] != original["fingerprint"]


def test_provenance_contract_version_changes_fingerprint():
    profile, observation, region, ai = _inputs()
    current = classification_input_provenance(profile, observation, region, ai)
    next_contract = classification_input_provenance(
        profile, observation, region, ai, version="classification-input-v3"
    )

    assert next_contract["fingerprint"] != current["fingerprint"]


def test_v1_provenance_ignores_family_detections_not_used_by_v1():
    profile, observation, region, ai = _inputs()
    original = classification_input_provenance(profile, observation, region, ai)
    with_irrelevant_detections = classification_input_provenance(
        profile,
        {**observation, "detections_recent": [{"id": "WEB-RATE-001", "points": 12}]},
        region,
        ai,
    )

    assert with_irrelevant_detections["fingerprint"] == original["fingerprint"]


def test_family_max_provenance_tracks_mode_effective_score_and_selected_rule_points():
    profile, observation, region, ai = _inputs()
    family_observation = {
        **observation,
        "classification_scoring_mode": "family_max",
        "classification_behavior_score": 10,
        "detections_recent": [
            {"id": "WEB-BURST-001", "points": 10},
            {"id": "WEB-RATE-001", "points": 12},
        ],
        "detections_24h": [{"id": "unused", "points": 99}],
    }
    original = classification_input_provenance(profile, family_observation, region, ai)
    canonical = original["canonical_inputs"]["observation"]
    assert canonical["scoring_mode"] == "family_max"
    assert canonical["behavior_score"] == 12
    assert canonical["effective_behavior_score"] == 10
    assert canonical["selected_rule_points"] == [
        {"rule_id": "WEB-BURST-001", "points": 10},
        {"rule_id": "WEB-RATE-001", "points": 12},
    ]

    changed = classification_input_provenance(
        profile,
        {**family_observation, "detections_recent": [{"id": "WEB-RATE-001", "points": 11}]},
        region,
        ai,
    )
    assert changed["fingerprint"] != original["fingerprint"]


def test_mapping_key_order_does_not_change_fingerprint():
    profile, observation, region, ai = _inputs()
    ordered = classification_input_provenance(profile, observation, region, ai)
    reversed_order = classification_input_provenance(
        dict(reversed(list(profile.items()))),
        dict(reversed(list(observation.items()))),
        {
            "updated_at": region["updated_at"],
            "conflict_indicators": [
                {key: value for key, value in reversed(list(region["conflict_indicators"][0].items()))}
            ],
            "country_name": region["country_name"],
        },
        dict(reversed(list(ai.items()))),
    )

    assert reversed_order["canonical_inputs"] == ordered["canonical_inputs"]
    assert reversed_order["fingerprint"] == ordered["fingerprint"]
