import base64
import hashlib
import io
import json
import stat

import pytest

from app.config.backup import BackupSettings
from scripts.ops.backup_postgres_physical import PhysicalBackupError, backup_postgres_physical, basebackup_command


class FakeUploader:
    def __init__(self):
        self.blocks = []
        self.commits = []
        self.manifests = []

    def put_block(self, key, block_id, data):
        self.blocks.append((key, block_id, data))

    def put_block_list(self, key, block_ids):
        self.commits.append((key, block_ids))

    def put_bytes(self, key, data, content_type="application/json"):
        self.manifests.append((key, json.loads(data)))


class FakeProcess:
    def __init__(self, payload, exit_code=0, stderr=b""):
        self.stdout = io.BytesIO(payload)
        self.stderr = io.BytesIO(stderr)
        self.exit_code = exit_code
        self.killed = False

    def poll(self):
        return self.exit_code if not self.killed else -9

    def wait(self):
        return self.exit_code if not self.killed else -9

    def kill(self):
        self.killed = True


def settings(**kwargs):
    return BackupSettings("account", "container", **kwargs)


def test_command_streams_tar_to_stdout_without_local_directory():
    command = basebackup_command("postgresql://redacted")
    assert command == [
        "pg_basebackup", "--dbname", "postgresql://redacted", "--pgdata=-",
        "--format=tar", "--wal-method=none", "--gzip", "--compress=3",
        "--manifest-checksums=SHA256", "--no-slot",
    ]


def test_streams_ordered_blocks_and_verifies_remote(monkeypatch):
    payload = b"0123456789abcdef"
    process = FakeProcess(payload, stderr=b"write-ahead log start point: 0/100\nwrite-ahead log stop point: 0/200\n")
    seen = []
    monkeypatch.setattr("scripts.ops.backup_postgres_physical.subprocess.Popen", lambda command, **kwargs: (seen.append(command) or process))
    uploader = FakeUploader()
    result = backup_postgres_physical(settings(part_size=5), "dsn", uploader=uploader,
                                       verifier=lambda settings, key: (len(payload), hashlib.sha256(payload).hexdigest()),
                                       backup_id="base-1", chunk_size=3)
    assert seen[0][4] == "--format=tar"
    assert [item[2] for item in uploader.blocks] == [b"01234", b"56789", b"abcde", b"f"]
    assert uploader.commits[0][1] == [base64.b64encode(f"{n:08d}".encode()).decode() for n in (1, 2, 3, 4)]
    assert result["backup_type"] == "postgresql_physical_base"
    assert result["bytes"] == len(payload)
    assert result["sha256"] == hashlib.sha256(payload).hexdigest()
    assert result["observed_wal_start_lsn"] == "0/100"
    assert result["observed_wal_stop_lsn"] == "0/200"
    assert uploader.manifests[0][0].endswith("manifests/base/base-1.json")


def test_nonzero_pg_basebackup_never_commits_or_manifests(monkeypatch):
    process = FakeProcess(b"partial", exit_code=2)
    monkeypatch.setattr("scripts.ops.backup_postgres_physical.subprocess.Popen", lambda command, **kwargs: process)
    uploader = FakeUploader()
    with pytest.raises(PhysicalBackupError, match="exit 2"):
        backup_postgres_physical(settings(), "dsn", uploader=uploader)
    assert not uploader.commits
    assert not uploader.manifests


def test_remote_mismatch_never_writes_manifest(monkeypatch):
    payload = b"base-payload"
    process = FakeProcess(payload)
    monkeypatch.setattr("scripts.ops.backup_postgres_physical.subprocess.Popen", lambda command, **kwargs: process)
    uploader = FakeUploader()
    with pytest.raises(PhysicalBackupError, match="SHA-256"):
        backup_postgres_physical(settings(), "dsn", uploader=uploader,
                                 verifier=lambda settings, key: (len(payload), "0" * 64))
    assert uploader.commits
    assert not uploader.manifests


def test_empty_stream_never_commits(monkeypatch):
    process = FakeProcess(b"")
    monkeypatch.setattr("scripts.ops.backup_postgres_physical.subprocess.Popen", lambda command, **kwargs: process)
    uploader = FakeUploader()
    with pytest.raises(PhysicalBackupError, match="empty"):
        backup_postgres_physical(settings(), "dsn", uploader=uploader)
    assert not uploader.commits
