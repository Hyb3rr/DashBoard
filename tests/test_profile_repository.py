from app.db import repositories


class _FakeConnection:
    def __init__(self):
        self.sql = []
        self.params = []

    def execute(self, sql, params=()):
        self.sql.append(sql)
        self.params.append(params)


class _Transaction:
    def __init__(self, connection):
        self.connection = connection

    def __enter__(self):
        return self.connection

    def __exit__(self, *exc):
        return False


def test_profile_upsert_refreshes_enrichment_fields_without_detection_state(monkeypatch):
    connection = _FakeConnection()
    monkeypatch.setattr(repositories, "transaction", lambda: _Transaction(connection))

    repositories.ProfileRepository().upsert({
        "ip": "192.0.2.10",
        "proxy_type": "vpn",
        "abuse_score": 42,
        "abuse_reports": 3,
        "reputation": [{"source": "provider", "label": "watch"}],
        "enrichment_status": "complete",
        "core_enrichment_status": "complete",
        "privacy_enrichment_status": "complete",
        "threat_enrichment_status": "complete",
        "provider_errors": [],
        "provider_status": {"provider": "ok"},
        "field_sources": {"country": ["geo"]},
        "next_retry_at": None,
        "enrichment_attempts": 2,
        "privacy_recheck_due_at": None,
        "sources": [{"name": "provider"}],
        "risk_score": 99,
        "risk_level": "bad",
        "evidence": ["detection-owned"],
    })

    conflict_sql = connection.sql[0]
    for column in (
        "proxy_type", "abuse_score", "abuse_reports", "reputation",
        "core_enrichment_status", "privacy_enrichment_status",
        "threat_enrichment_status", "provider_errors", "provider_status",
        "field_sources", "next_retry_at", "enrichment_attempts",
        "privacy_recheck_due_at", "sources",
    ):
        assert f"{column}=EXCLUDED.{column}" in conflict_sql

    assert "risk_score=EXCLUDED.risk_score" not in conflict_sql
    assert "risk_level=EXCLUDED.risk_level" not in conflict_sql
    assert "evidence=EXCLUDED.evidence" not in conflict_sql
