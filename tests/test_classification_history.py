from app.db.classification_history_repository import ClassificationHistoryRepository


class _Connection:
    def __init__(self):
        self.executed = []

    def execute(self, sql, params):
        self.executed.append((sql, params))


def test_history_records_label_transition_with_snapshot_and_idempotency_key():
    connection = _Connection()
    current = {
        "label": "good", "score": 0,
        "evidence": ["A — Broad web content enumeration (+15)", "C — stable attributed network (-20)"],
        "score_breakdown": {"behavior_a": 15, "trust_c": -20},
    }

    ClassificationHistoryRepository.record_transition(
        connection,
        event_key="traffic:live:batch-1:192.0.2.10",
        dataset_id="live",
        ip="192.0.2.10",
        source="traffic",
        changed_at="2026-09-28T10:00:00+00:00",
        previous_classification={"label": "medium", "score": 30},
        current_classification=current,
    )

    assert len(connection.executed) == 1
    sql, params = connection.executed[0]
    assert "ON CONFLICT (event_key) DO NOTHING" in sql
    assert params[:5] == (
        "traffic:live:batch-1:192.0.2.10", "live", "192.0.2.10", "traffic",
        "2026-09-28T10:00:00+00:00",
    )


def test_history_skips_score_updates_when_classification_label_did_not_change():
    connection = _Connection()

    ClassificationHistoryRepository.record_transition(
        connection,
        event_key="traffic:live:batch-2:192.0.2.10",
        dataset_id="live",
        ip="192.0.2.10",
        source="traffic",
        changed_at="2026-09-28T10:05:00+00:00",
        previous_classification={"label": "medium", "score": 30},
        current_classification={"label": "medium", "score": 35},
    )

    assert connection.executed == []
