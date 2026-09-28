from types import SimpleNamespace

from app.config.backup import BackupSettings
from scripts.ops import retention_synthetic as synthetic


def test_probe_fixture_uploads_only_under_unique_test_prefix(monkeypatch):
    uploaded = []
    monkeypatch.setattr(synthetic, "_put", lambda _uploader, key, body: uploaded.append((key, body)))

    manifests, keys = synthetic._upload_probe_fixture(object(), "sentinelhub/retention-test/run-1")

    assert len(manifests) == 16
    assert len(keys) == 81
    assert uploaded[-1][0] == "sentinelhub/retention-test/run-1/unknown-object.bin"
    assert all(key.startswith("sentinelhub/retention-test/run-1/") for key in keys)


def test_candidate_deletion_is_limited_to_planned_test_prefix(monkeypatch):
    deleted = []
    monkeypatch.setattr(synthetic, "_delete", lambda _settings, key: deleted.append(key) or 202)
    decisions = [
        SimpleNamespace(decision="KEEP", object_keys=("keep",)),
        SimpleNamespace(decision="DELETE_CANDIDATE", object_keys=(
            "sentinelhub/retention-test/run-2/postgres/dump",
            "sentinelhub/retention-test/run-2/manifests/postgres.json",
        )),
    ]

    result = synthetic._delete_candidates(
        BackupSettings(account="example", container="backup"),
        decisions,
        "sentinelhub/retention-test/run-2",
    )

    assert result == deleted
    assert len(deleted) == 2
    assert all(key.startswith("sentinelhub/retention-test/run-2/") for key in deleted)


def test_cleanup_attempts_all_objects_even_when_one_delete_fails(monkeypatch):
    attempted = []

    def delete(_settings, key):
        attempted.append(key)
        if key == "second":
            raise RuntimeError("simulated cleanup failure")

    monkeypatch.setattr(synthetic, "_delete", delete)
    settings = BackupSettings(account="example", container="backup")

    synthetic._cleanup_probe_objects(settings, ["first", "second", "third"])

    assert attempted == ["third", "second", "first"]


def test_delete_refuses_keys_outside_retention_test_prefix(monkeypatch):
    monkeypatch.setattr(synthetic, "_credential", lambda _settings: (_ for _ in ()).throw(AssertionError("credentials must not be read")))
    settings = BackupSettings(account="example", container="backup", prefix="sentinelhub/production")

    try:
        synthetic._delete(settings, "sentinelhub/production/backup.dump")
    except RuntimeError as exc:
        assert "refused outside retention-test prefix" in str(exc)
    else:
        raise AssertionError("unsafe prefix was not rejected")
