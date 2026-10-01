from datetime import datetime, timedelta, timezone
import hashlib

import pytest

from app.db import repositories
from app.db import detection_repository
from app.db.alert_repository import (
    create_classification_alert,
    persist_classification_alert_and_notification,
    should_create_monitored_recurrence,
)
from app.db.json_codec import json_bytes
from app.core.failpoints import NoopFailpoint
from app.services import profiles
from app.services.dispositions import automatic_transition


class Result:
    def __init__(self, row=None):
        self.row = row

    def fetchone(self):
        return self.row


def _plain_json(value):
    return value.obj if hasattr(value, "obj") else value


class Connection:
    """Small deterministic SQL seam for disposition and alert repository tests."""

    def __init__(self, disposition=None, latest_medium=None, latest_critical=None, insert_alert=True):
        self.disposition = disposition
        self.latest_medium = latest_medium
        self.latest_critical = latest_critical
        self.insert_alert = insert_alert
        self.executed = []
        self.alert_args = None
        self.outbox_args = []

    def execute(self, sql, args=()):
        compact = " ".join(sql.split())
        self.executed.append((compact, args))
        if "FROM ip_dispositions" in compact and compact.startswith("SELECT"):
            if "SELECT state FROM" in compact:
                return Result({"state": self.disposition["state"]} if self.disposition else None)
            return Result(dict(self.disposition) if self.disposition else None)
        if compact.startswith("SELECT pg_advisory_xact_lock"):
            return Result()
        if compact.startswith("UPDATE ip_dispositions"):
            state, suggestion, updated_at, history, ip, expected_state = args
            if self.disposition and self.disposition["state"] == expected_state:
                self.disposition.update({
                    "state": state,
                    "suggested_state": suggestion,
                    "updated_at": updated_at,
                    "history": _plain_json(history),
                })
            return Result()
        if compact.startswith("INSERT INTO ip_dispositions"):
            if "ON CONFLICT(ip) DO NOTHING" in compact:
                if self.disposition:
                    return Result()
                ip, state, suggestion, updated_at, history = args
                self.disposition = {
                    "ip": ip, "state": state, "suggested_state": suggestion,
                    "updated_at": updated_at, "assigned_to": None, "note": None,
                    "history": _plain_json(history),
                }
                return Result({"ip": ip})
            ip, state, suggestion, assigned_to, note, updated_at, history = args
            new_history = _plain_json(history)
            if self.disposition:
                self.disposition.update({
                    "state": state, "suggested_state": suggestion,
                    "assigned_to": assigned_to, "note": note,
                    "updated_at": updated_at, "history": new_history,
                })
            else:
                self.disposition = {
                    "ip": ip, "state": state, "suggested_state": suggestion,
                    "assigned_to": assigned_to, "note": note,
                    "updated_at": updated_at, "history": new_history,
                }
            return Result()
        if "SELECT created_at,evidence_fingerprint FROM alerts" in compact:
            if "severity='critical'" in compact:
                return Result(dict(self.latest_critical) if self.latest_critical else None)
            return Result(dict(self.latest_medium) if self.latest_medium else None)
        if "SELECT created_at FROM alerts" in compact:
            return Result(dict(self.latest_critical) if self.latest_critical else None)
        if compact.startswith("INSERT INTO alerts"):
            self.alert_args = args
            return Result({"id": 123} if self.insert_alert else None)
        if compact.startswith("INSERT INTO alert_outbox"):
            self.outbox_args.append(args)
            return Result()
        if compact.startswith("SELECT * FROM ip_dispositions"):
            return Result(dict(self.disposition) if self.disposition else None)
        return Result()


@pytest.mark.parametrize(
    ("state", "label", "reason_type", "expected"),
    [
        ("new", "medium", None, ("monitor", "medium_classification")),
        ("new", "critical", None, ("investigate", "critical_classification")),
        ("monitor", "critical", "classification_transition", ("investigate", "critical_classification")),
        ("monitor", "medium", "classification_transition", ("investigate", "medium_classification")),
        ("monitor", "medium", "monitored_recurrence", ("investigate", "monitored_recurrence")),
        ("monitor", "medium", None, None),
        ("investigate", "medium", "monitored_recurrence", None),
        ("escalate", "critical", "classification_transition", None),
        ("resolved", "critical", "classification_transition", None),
    ],
)
def test_automatic_transition_policy_is_monotonic(state, label, reason_type, expected):
    assert automatic_transition(state, label, reason_type) == expected


def test_monitored_recurrence_requires_new_medium_evidence_after_cooldown():
    now = datetime(2026, 9, 29, 12, tzinfo=timezone.utc)
    latest = now - timedelta(minutes=31)

    assert not should_create_monitored_recurrence("monitor", "medium", "medium", "same", "same", latest, now)
    assert not should_create_monitored_recurrence("monitor", "medium", "medium", "new", "old", now - timedelta(minutes=29), now)
    assert should_create_monitored_recurrence("monitor", "medium", "medium", "new", "old", latest, now)
    assert not should_create_monitored_recurrence("new", "medium", "medium", "new", "old", latest, now)
    assert not should_create_monitored_recurrence("monitor", "low", "low", "new", "old", latest, now)
    assert not should_create_monitored_recurrence("monitor", "medium", "medium", "new", None, None, now)
    assert should_create_monitored_recurrence(
        "monitor", "medium", "medium", "new", None, now - timedelta(minutes=31), now,
    )


@pytest.mark.parametrize(
    ("state", "label", "alert_result", "expected"),
    [
        (None, "medium", None, ("new", "monitor", "medium_classification")),
        (None, "critical", None, ("new", "investigate", "critical_classification")),
        ("monitor", "critical", {"created": True, "reason_type": "classification_transition"},
         ("monitor", "investigate", "critical_classification")),
        ("monitor", "medium", {"created": True, "reason_type": "monitored_recurrence"},
         ("monitor", "investigate", "monitored_recurrence")),
        ("investigate", "medium", {"created": True, "reason_type": "monitored_recurrence"}, None),
        ("escalate", "critical", {"created": True, "reason_type": "classification_transition"}, None),
        ("resolved", "critical", {"created": True, "reason_type": "classification_transition"}, None),
    ],
)
def test_automatic_transition_persists_only_allowed_states(state, label, alert_result, expected):
    existing = {"ip": "203.0.113.10", "state": state, "assigned_to": "analyst@sentinel",
                "note": "keep this", "history": [{"actor": "analyst", "from": "new", "to": state}]}
    conn = Connection(disposition=existing if state else None)
    now = datetime(2026, 9, 29, 12, tzinfo=timezone.utc)

    result = repositories.DispositionRepository.apply_automatic_transition(
        conn, ip="203.0.113.10", classification_label=label,
        alert_result=alert_result, now=now,
    )

    if expected is None:
        assert result is None
        assert conn.disposition["state"] == state
        assert conn.disposition["history"] == existing["history"]
    else:
        assert (result["from"], result["to"], result["reason"]) == expected
        history = conn.disposition["history"]
        assert history[-1] == {
            "at": now.isoformat(), "actor": "system", "from": expected[0],
            "to": expected[1], "reason": expected[2],
        }
        if state:
            assert conn.disposition["assigned_to"] == "analyst@sentinel"
            assert conn.disposition["note"] == "keep this"


def test_monitored_recurrence_alert_returns_created_metadata_and_reason():
    now = datetime(2026, 9, 29, 12, tzinfo=timezone.utc)
    conn = Connection(
        disposition={"state": "monitor"},
        latest_medium={"created_at": now - timedelta(minutes=31), "evidence_fingerprint": "old-fingerprint"},
    )
    result = create_classification_alert(
        conn, dataset_id="live", batch_id="batch-2", ip="203.0.113.10",
        old_label="medium", old_score=35,
        classification={"label": "medium", "score": 38}, evidence=["new evidence"], created_at=now,
        recurrence_observed_at=now,
    )

    assert result == {"created": True, "reason_type": "monitored_recurrence"}
    assert conn.alert_args[2] == "monitored_recurrence"
    assert conn.alert_args[3] == "Monitored activity repeated for 203.0.113.10"
    assert conn.alert_args[9].startswith("classification:203.0.113.10:medium:monitored_recurrence:")


def test_low_to_medium_classification_transition_advances_monitor_to_investigate():
    conn = Connection(disposition={"state": "monitor", "history": []})
    now = datetime(2026, 9, 29, 12, tzinfo=timezone.utc)
    alert_result = create_classification_alert(
        conn, dataset_id="live", batch_id="batch-low-medium", ip="203.0.113.14",
        old_label="low", old_score=12,
        classification={"label": "medium", "score": 34}, evidence=["medium evidence"], created_at=now,
    )
    transition = repositories.DispositionRepository.apply_automatic_transition(
        conn, ip="203.0.113.14", classification_label="medium",
        alert_result=alert_result, now=now,
    )

    assert alert_result == {"created": True, "reason_type": "classification_transition"}
    assert transition == {"from": "monitor", "to": "investigate", "reason": "medium_classification"}
    assert conn.disposition["state"] == "investigate"


def test_monitored_recurrence_repository_suppresses_same_fingerprint_after_cooldown():
    now = datetime(2026, 9, 29, 12, tzinfo=timezone.utc)
    evidence = ["same"]
    fingerprint = hashlib.sha256(json_bytes(evidence)).hexdigest()
    latest = {"created_at": now - timedelta(minutes=31), "evidence_fingerprint": fingerprint}
    conn = Connection(disposition={"state": "monitor"}, latest_medium=latest)
    result = create_classification_alert(
        conn, dataset_id="live", batch_id="batch-3", ip="203.0.113.10",
        old_label="medium", old_score=35,
        classification={"label": "medium", "score": 38}, evidence=evidence, created_at=now,
    )

    assert result == {"created": False, "reason_type": None}
    assert conn.alert_args is None


def test_monitored_recurrence_repository_suppresses_changed_evidence_inside_cooldown():
    now = datetime(2026, 9, 29, 12, tzinfo=timezone.utc)
    conn = Connection(
        disposition={"state": "monitor"},
        latest_medium={"created_at": now - timedelta(minutes=29), "evidence_fingerprint": "old"},
    )
    result = create_classification_alert(
        conn, dataset_id="live", batch_id="batch-4", ip="203.0.113.10",
        old_label="medium", old_score=35,
        classification={"label": "medium", "score": 38}, evidence=["new"], created_at=now,
    )

    assert result == {"created": False, "reason_type": None}
    assert conn.alert_args is None


def test_manual_monitor_uses_disposition_time_when_no_medium_alert_exists():
    now = datetime(2026, 9, 29, 12, tzinfo=timezone.utc)
    conn = Connection(
        disposition={"state": "monitor", "updated_at": now - timedelta(minutes=31), "history": []},
    )
    alert_result = create_classification_alert(
        conn, dataset_id="live", batch_id="manual-monitor", ip="203.0.113.15",
        old_label="medium", old_score=35,
        classification={"label": "medium", "score": 39}, evidence=["new manual-monitor evidence"], created_at=now,
        recurrence_observed_at=now,
    )
    transition = repositories.DispositionRepository.apply_automatic_transition(
        conn, ip="203.0.113.15", classification_label="medium",
        alert_result=alert_result, now=now,
    )

    assert alert_result == {"created": True, "reason_type": "monitored_recurrence"}
    assert transition == {"from": "monitor", "to": "investigate", "reason": "monitored_recurrence"}
    assert conn.disposition["state"] == "investigate"


def test_monitored_recurrence_cooldown_uses_later_of_alert_and_disposition_times():
    now = datetime(2026, 9, 29, 12, tzinfo=timezone.utc)
    evidence = ["new evidence"]
    blocked_conn = Connection(
        disposition={"state": "monitor", "updated_at": now - timedelta(minutes=40), "history": []},
        latest_medium={"created_at": now - timedelta(minutes=20), "evidence_fingerprint": "old"},
    )
    blocked = create_classification_alert(
        blocked_conn, dataset_id="live", batch_id="later-alert", ip="203.0.113.16",
        old_label="medium", old_score=35,
        classification={"label": "medium", "score": 39}, evidence=evidence, created_at=now,
        recurrence_observed_at=now,
    )
    allowed_conn = Connection(
        disposition={"state": "monitor", "updated_at": now - timedelta(minutes=40), "history": []},
        latest_medium={"created_at": now - timedelta(minutes=31), "evidence_fingerprint": "old"},
    )
    allowed = create_classification_alert(
        allowed_conn, dataset_id="live", batch_id="later-disposition", ip="203.0.113.17",
        old_label="medium", old_score=35,
        classification={"label": "medium", "score": 39}, evidence=evidence, created_at=now,
        recurrence_observed_at=now,
    )

    assert blocked == {"created": False, "reason_type": None}
    assert blocked_conn.alert_args is None
    assert allowed == {"created": True, "reason_type": "monitored_recurrence"}

    replayed_conn = Connection(
        disposition={"state": "monitor", "updated_at": now - timedelta(minutes=40), "history": []},
        latest_medium={"created_at": now - timedelta(minutes=31), "evidence_fingerprint": "old"},
    )
    replayed = create_classification_alert(
        replayed_conn, dataset_id="live", batch_id="replayed-before-baseline", ip="203.0.113.18",
        old_label="medium", old_score=35,
        classification={"label": "medium", "score": 39}, evidence=evidence, created_at=now,
        recurrence_observed_at=now - timedelta(minutes=32),
    )
    assert replayed == {"created": False, "reason_type": None}
    assert replayed_conn.alert_args is None


def test_alert_dedupe_result_and_critical_outbox_behavior_are_preserved():
    now = datetime(2026, 9, 29, 12, tzinfo=timezone.utc)
    conn = Connection(insert_alert=False)
    result = persist_classification_alert_and_notification(
        conn, dataset_id="live", batch_id="batch-critical", ip="203.0.113.11",
        old_label="medium", old_score=35,
        classification={"label": "critical", "score": 90}, evidence=["critical evidence"],
        created_at=now,
    )

    assert result == {"created": False, "reason_type": None}
    assert len(conn.outbox_args) == 1
    assert conn.outbox_args[0][1].obj["classification"]["label"] == "critical"
    assert conn.outbox_args[0][3] == "classification_critical:live:203.0.113.11:batch-critical"


def test_monitor_critical_transition_alert_and_investigation_are_atomic():
    conn = Connection(disposition={"state": "monitor", "history": []})
    now = datetime(2026, 9, 29, 12, tzinfo=timezone.utc)
    alert_result = persist_classification_alert_and_notification(
        conn, dataset_id="live", batch_id="batch-critical", ip="203.0.113.13",
        old_label="medium", old_score=40,
        classification={"label": "critical", "score": 90}, evidence=["critical evidence"],
        created_at=now,
    )
    transition = repositories.DispositionRepository.apply_automatic_transition(
        conn, ip="203.0.113.13", classification_label="critical",
        alert_result=alert_result, now=now,
    )

    assert alert_result == {"created": True, "reason_type": "classification_transition"}
    assert conn.alert_args[2] == "classification_transition"
    assert transition == {"from": "monitor", "to": "investigate", "reason": "critical_classification"}
    assert conn.disposition["state"] == "investigate"
    assert conn.disposition["history"][-1]["actor"] == "system"
    assert len(conn.outbox_args) == 1


def test_manual_disposition_set_keeps_existing_history_contract(monkeypatch):
    conn = Connection(disposition={
        "ip": "203.0.113.12", "state": "monitor", "assigned_to": "old@sentinel",
        "note": "old note", "history": [{"actor": "analyst", "from": "new", "to": "monitor"}],
    })

    class Scope:
        def __enter__(self):
            return conn

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(repositories, "transaction", lambda: Scope())
    result = repositories.DispositionRepository().set(
        "203.0.113.12", "investigate", "new@sentinel", "reviewed", "analyst", "critical",
    )

    assert result["state"] == "investigate"
    assert result["assigned_to"] == "new@sentinel"
    assert result["note"] == "reviewed"
    assert result["history"][-1]["actor"] == "analyst"
    assert result["history"][-1]["from"] == "monitor"
    assert result["history"][-1]["to"] == "investigate"


@pytest.mark.parametrize(
    ("recent_last_seen", "expected_recurrence_at"),
    [(None, None), ("2026-09-29T11:59:00+00:00", "2026-09-29T11:59:00+00:00")],
)
def test_traffic_classification_wires_alert_and_disposition_on_same_connection(
    monkeypatch, recent_last_seen, expected_recurrence_at,
):
    conn = Connection()
    alert_result = {"created": True, "reason_type": "classification_transition"}
    calls = {}

    monkeypatch.setattr(detection_repository, "classify_ip", lambda *args: {
        "label": "critical", "score": 91, "confidence": 90, "evidence": ["critical evidence"],
    })
    monkeypatch.setattr(
        detection_repository.ClassificationHistoryRepository, "record_transition",
        lambda connection, **kwargs: calls.setdefault("history_conn", connection),
    )
    monkeypatch.setattr(
        detection_repository, "persist_classification_alert_and_notification",
        lambda connection, **kwargs: (
            calls.setdefault("alert_conn", connection),
            calls.setdefault("alert_kwargs", kwargs),
            alert_result,
        )[-1],
    )

    def apply_auto(connection, **kwargs):
        calls["disposition_conn"] = connection
        calls["disposition_kwargs"] = kwargs

    monkeypatch.setattr(
        repositories.DispositionRepository, "apply_automatic_transition", staticmethod(apply_auto),
    )
    now = datetime(2026, 9, 29, 12, tzinfo=timezone.utc)
    detection_repository.PgDetectionRepository._persist_ip_detection(
        conn, dataset_id="live", batch_id="batch-1", ip="203.0.113.20",
        payload={"ruleset_hash": "rules-v1", "recent_last_seen": recent_last_seen}, profile={},
        previous={"label": "medium", "score": 40}, now=now, failpoint=NoopFailpoint(),
    )

    assert calls["alert_conn"] is conn
    assert calls["disposition_conn"] is conn
    assert calls["disposition_kwargs"]["classification_label"] == "critical"
    assert calls["disposition_kwargs"]["alert_result"] == alert_result
    assert calls["disposition_kwargs"]["now"] == now
    assert calls["alert_kwargs"]["recurrence_observed_at"] == expected_recurrence_at


def test_critical_recurrence_requires_recent_traffic_and_changed_evidence():
    now = datetime(2026, 9, 29, 12, tzinfo=timezone.utc)
    old_evidence = ["sensitive probe"]
    old_fingerprint = hashlib.sha256(json_bytes(old_evidence)).hexdigest()
    prior_alert = {"created_at": now - timedelta(minutes=31), "evidence_fingerprint": old_fingerprint}
    shared = dict(
        dataset_id="live", batch_id="critical-repeat", ip="203.0.113.30",
        old_label="critical", old_score=65,
        classification={"label": "critical", "score": 65}, created_at=now,
    )

    stale_enrichment = Connection(latest_critical=prior_alert)
    stale_result = create_classification_alert(
        stale_enrichment, evidence=["changed enrichment evidence"], **shared,
    )
    same_evidence = Connection(latest_critical=prior_alert)
    same_result = create_classification_alert(
        same_evidence, evidence=old_evidence, recurrence_observed_at=now, **shared,
    )
    fresh_traffic = Connection(latest_critical=prior_alert)
    changed_result = create_classification_alert(
        fresh_traffic, evidence=["new sensitive probe"], recurrence_observed_at=now, **shared,
    )

    assert stale_result == {"created": False, "reason_type": None}
    assert stale_enrichment.alert_args is None
    assert same_result == {"created": False, "reason_type": None}
    assert same_evidence.alert_args is None
    assert changed_result == {"created": True, "reason_type": "critical_recurrence"}

    replayed_traffic = Connection(latest_critical=prior_alert)
    replayed_result = create_classification_alert(
        replayed_traffic, evidence=["new sensitive probe"],
        recurrence_observed_at=now - timedelta(minutes=40), **shared,
    )
    assert replayed_result == {"created": False, "reason_type": None}


def test_critical_classification_transition_does_not_need_recurrence_gate():
    now = datetime(2026, 9, 29, 12, tzinfo=timezone.utc)
    conn = Connection()
    result = create_classification_alert(
        conn, dataset_id="live", batch_id="critical-rise", ip="203.0.113.31",
        old_label="medium", old_score=40,
        classification={"label": "critical", "score": 65}, evidence=["critical transition"],
        created_at=now,
    )

    assert result == {"created": True, "reason_type": "classification_transition"}


def test_enrichment_reclassification_does_not_enable_activity_recurrence(monkeypatch):
    observation = {"behavior_score": 30, "requests": 120}

    class ProfileConnection:
        def __init__(self):
            self.calls = []

        def execute(self, sql, args=()):
            compact = " ".join(sql.split())
            self.calls.append((compact, args))
            if compact.startswith("SELECT payload FROM ip_observations_state"):
                return Result({"payload": observation})
            if compact.startswith("SELECT label,score FROM ip_classification_state"):
                return Result({"label": "medium", "score": 30})
            return Result()

    conn = ProfileConnection()
    alert_result = {"created": False, "reason_type": None}
    calls = {}
    monkeypatch.setattr(profiles, "classify_ip", lambda *args: {
        "label": "medium", "score": 30, "confidence": 70, "evidence": ["new evidence"],
    })
    monkeypatch.setattr(
        profiles, "persist_classification_alert_and_notification",
        lambda connection, **kwargs: (
            calls.setdefault("alert_conn", connection),
            calls.setdefault("alert_kwargs", kwargs),
            alert_result,
        )[-1],
    )

    def apply_auto(connection, **kwargs):
        calls["disposition_conn"] = connection
        calls["disposition_kwargs"] = kwargs

    monkeypatch.setattr(
        repositories.DispositionRepository, "apply_automatic_transition", staticmethod(apply_auto),
    )
    profiles._reclassify_after_enrichment(conn, "203.0.113.21", {})

    assert calls["alert_conn"] is conn
    assert calls["disposition_conn"] is conn
    assert calls["disposition_kwargs"]["classification_label"] == "medium"
    assert calls["disposition_kwargs"]["alert_result"] == alert_result
    assert calls["alert_kwargs"].get("recurrence_observed_at") is None
    assert not any("ip_change_log" in sql for sql, _ in conn.calls)
