from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.core.classification_provenance import (
    CLASSIFICATION_INPUT_VERSION,
    classification_input_provenance,
)
from app.core.failpoints import NoopFailpoint
from app.core.intelligence import classify_ip
from app.db import detection_repository, repositories
from app.services import profiles


class _Result:
    def __init__(self, row=None):
        self._row = row

    def fetchone(self):
        return self._row


class _Connection:
    def __init__(self, observation=None, previous=None):
        self.calls = []
        self.observation = observation or {}
        self.previous = previous or {"label": "low", "score": 10}

    def execute(self, sql, params=()):
        compact = " ".join(sql.split())
        self.calls.append((compact, params))
        if compact.startswith("SELECT payload FROM ip_observations_state"):
            return _Result({"payload": self.observation})
        if compact.startswith("SELECT label,score FROM ip_classification_state"):
            return _Result(self.previous)
        return _Result()


class _TransactionalConnection(_Connection):
    def __init__(self, current):
        super().__init__()
        self.current = dict(current)
        self.pending = None

    @contextmanager
    def transaction(self):
        self.pending = dict(self.current)
        try:
            yield self
        except Exception:
            self.pending = None
            raise
        else:
            self.current = self.pending
            self.pending = None

    def execute(self, sql, params=()):
        result = super().execute(sql, params)
        compact = " ".join(sql.split())
        if compact.startswith("INSERT INTO ip_classification_state"):
            self.pending = {
                "label": params[1],
                "score": params[2],
                "confidence": params[3],
                "input_contract_version": params[4],
                "input_fingerprint": params[5],
                "updated_at": params[6],
            }
        return result


class _FailAt:
    def __init__(self, target):
        self.target = target

    def hit(self, name):
        if name == self.target:
            raise RuntimeError(name)


def _stub_disposition_side_effects(monkeypatch):
    monkeypatch.setattr(
        detection_repository, "persist_classification_alert_and_notification",
        lambda *args, **kwargs: {"created": False, "reason_type": None},
    )
    monkeypatch.setattr(
        profiles, "persist_classification_alert_and_notification",
        lambda *args, **kwargs: {"created": False, "reason_type": None},
    )
    monkeypatch.setattr(
        repositories.DispositionRepository,
        "apply_automatic_transition",
        staticmethod(lambda *args, **kwargs: None),
    )


def _observation(score):
    return {
        "ruleset_hash": "rules-v1",
        "recent_behavior_score": score,
        "recent_requests": 20,
        "recent_sensitive_probe_requests": 0,
        "recent_behavior_evidence": ["rate evidence"],
        "rule_coverage": True,
    }


def _classification_upserts(connection):
    return [
        (sql, params)
        for sql, params in connection.calls
        if sql.startswith("INSERT INTO ip_classification_state")
    ]


def test_traffic_classification_persists_provenance_from_classifier_inputs(monkeypatch):
    _stub_disposition_side_effects(monkeypatch)
    connection = _Connection()
    profile = {"is_proxy": True, "organization": "Example", "organization_confidence": 80}
    observation = _observation(10)
    now = datetime(2026, 9, 30, tzinfo=timezone.utc)

    detection_repository.PgDetectionRepository._persist_ip_detection(
        connection,
        dataset_id="live",
        batch_id="batch-a",
        ip="203.0.113.60",
        payload=observation,
        profile=profile,
        previous={"label": "low", "score": 10},
        now=now,
        failpoint=NoopFailpoint(),
    )

    sql, params = _classification_upserts(connection)[0]
    expected = classification_input_provenance(profile, observation, {}, None)
    expected_classification = classify_ip(profile, observation, {}, None)
    assert "input_contract_version,input_fingerprint,updated_at" in sql
    assert params[1:4] == (
        expected_classification["label"],
        expected_classification["score"],
        expected_classification["confidence"],
    )
    assert params[4:] == (expected["version"], expected["fingerprint"], now)


def test_enrichment_reclassification_persists_provenance_from_same_inputs(monkeypatch):
    _stub_disposition_side_effects(monkeypatch)
    observation = _observation(10)
    connection = _Connection(observation, {"label": "low", "score": 10})
    profile = {
        "is_proxy": True,
        "organization": "Example",
        "organization_confidence": 80,
        "core_enrichment_status": "complete",
        "privacy_enrichment_status": "complete",
    }

    profiles._reclassify_after_enrichment(connection, "203.0.113.61", profile)

    sql, params = _classification_upserts(connection)[0]
    expected = classification_input_provenance(profile, observation, {}, None)
    expected_classification = classify_ip(profile, observation, {}, None)
    assert "input_contract_version,input_fingerprint,updated_at" in sql
    assert params[1:4] == (
        expected_classification["label"],
        expected_classification["score"],
        expected_classification["confidence"],
    )
    assert params[4] == expected["version"]
    assert params[5] == expected["fingerprint"]
    assert params[6] is not None


def test_changed_traffic_input_updates_score_and_fingerprint_together(monkeypatch):
    _stub_disposition_side_effects(monkeypatch)
    connection = _Connection()
    profile = {"is_proxy": False}
    now = datetime(2026, 9, 30, tzinfo=timezone.utc)

    for score in (10, 20):
        detection_repository.PgDetectionRepository._persist_ip_detection(
            connection,
            dataset_id="live",
            batch_id=f"batch-{score}",
            ip="203.0.113.62",
            payload=_observation(score),
            profile=profile,
            previous={"label": "low", "score": score},
            now=now,
            failpoint=NoopFailpoint(),
        )

    upserts = _classification_upserts(connection)
    assert [params[2] for _, params in upserts] == [10, 20]
    assert [params[4] for _, params in upserts] == [CLASSIFICATION_INPUT_VERSION] * 2
    assert upserts[0][1][5] != upserts[1][1][5]


def test_failpoint_rolls_back_score_and_provenance_as_one_row_update(monkeypatch):
    _stub_disposition_side_effects(monkeypatch)
    previous = {
        "label": "low",
        "score": 10,
        "confidence": 70,
        "input_contract_version": "classification-input-v1",
        "input_fingerprint": "old-fingerprint",
        "updated_at": datetime(2026, 9, 29, tzinfo=timezone.utc),
    }
    connection = _TransactionalConnection(previous)

    with pytest.raises(RuntimeError, match="after_classification"):
        with connection.transaction():
            detection_repository.PgDetectionRepository._persist_ip_detection(
                connection,
                dataset_id="live",
                batch_id="batch-fail",
                ip="203.0.113.63",
                payload=_observation(30),
                profile={"is_proxy": True},
                previous={"label": "low", "score": 10},
                now=datetime(2026, 9, 30, tzinfo=timezone.utc),
                failpoint=_FailAt("after_classification"),
            )

    assert connection.current == previous
    _, params = _classification_upserts(connection)[0]
    assert params[2] == 40
    assert params[5] != "old-fingerprint"


def test_migration_leaves_historical_provenance_null_without_backfill():
    migration = Path("infra/postgres/042_classification_provenance.sql").read_text()

    assert "ADD COLUMN IF NOT EXISTS input_contract_version TEXT" in migration
    assert "ADD COLUMN IF NOT EXISTS input_fingerprint TEXT" in migration
    assert "UPDATE ip_classification_state" not in migration.upper()
    assert "DEFAULT" not in migration.upper()
    assert "NOT NULL" not in migration.upper()
