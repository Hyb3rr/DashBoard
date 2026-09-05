import hashlib

import pytest

from app.config.backup import BackupSettings
from scripts.ops.postgres_wal_shipper import ship_wal, spool_metrics


def settings():
    return BackupSettings("account", "container", tenant_id="tenant", client_id="client", client_secret="secret")


class FakeUploader:
    def __init__(self):
        self.uploads = []
        self.manifests = []

    def upload_file(self, key, path):
        self.uploads.append((key, path.read_bytes()))
        return "uploaded"

    def put_manifest(self, key, data):
        self.manifests.append((key, data))
        return "uploaded"


def test_ship_wal_verifies_and_deletes_only_after_manifest(tmp_path):
    payload = b"wal-segment"
    wal = tmp_path / "000000010000000000000001"
    wal.write_bytes(payload)
    uploader = FakeUploader()
    result = ship_wal(settings(), "dsn", tmp_path, uploader=uploader,
                      switcher=lambda dsn: "0/2000000",
                      verifier=lambda settings, key: (len(payload), hashlib.sha256(payload).hexdigest()))
    assert result["status"] == "completed"
    assert result["verified_wal"] == [wal.name]
    assert not wal.exists()
    assert uploader.uploads[0][0] == "sentinelhub/postgres-pitr/wal/" + wal.name
    assert len(uploader.manifests) == 1
    assert b'"status": "completed"' in uploader.manifests[0][1]


def test_remote_mismatch_preserves_local_wal(tmp_path):
    wal = tmp_path / "000000010000000000000002"
    wal.write_bytes(b"wal")
    uploader = FakeUploader()
    with pytest.raises(RuntimeError, match="verification mismatch"):
        ship_wal(settings(), "dsn", tmp_path, uploader=uploader,
                 switcher=lambda dsn: "0/3000000",
                 verifier=lambda settings, key: (3, "0" * 64))
    assert wal.exists()
    assert not uploader.manifests


def test_ship_wal_is_idempotent_for_empty_backlog(tmp_path):
    calls = []
    result = ship_wal(settings(), "dsn", tmp_path, uploader=FakeUploader(),
                      switcher=lambda dsn: calls.append(dsn) or "0/4000000")
    assert result["verified_wal"] == []
    assert result["before"] == result["after"] == {
        "pending_wal_count": 0,
        "pending_wal_bytes": 0,
        "oldest_pending_wal_age_seconds": 0.0,
    }
    assert calls == ["dsn"]


def test_spool_metrics_ignores_partial_and_unknown_files(tmp_path):
    (tmp_path / "000000010000000000000003").write_bytes(b"wal")
    (tmp_path / ".partial").write_bytes(b"ignore")
    (tmp_path / "not-a-wal").write_bytes(b"ignore")
    metrics = spool_metrics(tmp_path)
    assert metrics["pending_wal_count"] == 1
    assert metrics["pending_wal_bytes"] == 3
