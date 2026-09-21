from app.db.repositories import _alert_evidence_for_classification


def test_alert_evidence_uses_selected_classification_window_not_lifetime_observation():
    classification = {"evidence": ["recent 1h probe"]}
    observation = {
        "behavior_evidence": ["historical lifetime activity"],
        "recent_behavior_evidence": ["recent 1h probe"],
    }

    assert _alert_evidence_for_classification(classification, observation) == ["recent 1h probe"]


def test_alert_evidence_falls_back_to_selected_recent_evidence():
    assert _alert_evidence_for_classification(
        {}, {"behavior_evidence": ["historical"], "recent_behavior_evidence": ["recent"]}
    ) == ["recent"]
