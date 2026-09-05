import base64
from datetime import datetime, timezone
import hashlib
import io
import json
import stat

import pytest

from app.config.backup import BackupSettings
from scripts.ops.backup_clickhouse import _verify_remote_blob, backup_clickhouse
from scripts.ops.backup_postgres import AzureBlobUploader, backup_postgres
from scripts.ops.backup_set import backup_set
from scripts.ops.retention import plan_retention


class FakeBlob:
    def __init__(self):
        self.blocks, self.commits, self.uploads = [], [], []

    def stage_block(self, block_id, data):
        self.blocks.append((block_id, data))

    def commit_block_list(self, block_ids):
        self.commits.append(block_ids)

    def upload_blob(self, data, **kwargs):
        self.uploads.append((data, kwargs))


class FakeContainer:
    def __init__(self):
        self.blobs = {}

    def get_blob_client(self, key):
        return self.blobs.setdefault(key, FakeBlob())


class FakeService:
    def __init__(self):
        self.container = FakeContainer()

    def get_container_client(self, name):
        return self.container


class FakeUploader:
    def __init__(self, fail_block=False, fail_commit=False):
        self.blocks, self.commits, self.manifests = [], [], []
        self.fail_block, self.fail_commit = fail_block, fail_commit

    def put_block(self, key, block_id, data):
        if self.fail_block:
            raise RuntimeError("block failure")
        self.blocks.append((key, block_id, data))

    def put_block_list(self, key, block_ids):
        if self.fail_commit:
            raise RuntimeError("commit failure")
        self.commits.append((key, block_ids))

    def put_bytes(self, key, data, content_type="application/json"):
        self.manifests.append((key, json.loads(data)))


class FakeClickHouseClient:
    def __init__(self, artifact, fail=False):
        self.artifact, self.fail, self.commands = artifact, fail, []

    def command(self, query):
        self.commands.append(query)
        if self.fail:
            raise RuntimeError("native backup failure")
        self.artifact.parent.mkdir(parents=True, exist_ok=True)
        self.artifact.write_bytes(b"native-clickhouse-backup")


class FakeRemoteBlob:
    def __init__(self, payload):
        self.payload = payload

    def get_blob_properties(self):
        return type("Properties", (), {"size": len(self.payload)})()

    def download_blob(self):
        payload = self.payload
        return type("Download", (), {"readall": lambda self: payload})()


class FakeClickHouseUploader:
    def __init__(self, remote_size=None, fail=False):
        self.remote_size, self.fail = remote_size, fail
        self.uploads, self.manifests = [], []
        self.remote_payload = b"native-clickhouse-backup"

    def put_bytes(self, key, data, content_type="application/json"):
        if self.fail:
            raise RuntimeError("upload failure")
        self.uploads.append((key, data, content_type))
        if not key.endswith(".json"):
            self.remote_payload = data if self.remote_size is None else data[:self.remote_size]
        if key.endswith(".json"):
            self.manifests.append(json.loads(data))

    def _blob(self, key):
        return FakeRemoteBlob(self.remote_payload)


class FakeHttpResponse:
    def __init__(self, status, payload, content_length=None):
        self.status = status
        self.payload = payload
        self.content_length = str(len(payload) if content_length is None else content_length)

    def getheader(self, name):
        return self.content_length if name == "Content-Length" else None

    def read(self, size=-1):
        payload, self.payload = self.payload, b""
        return payload


class FakeHttpsConnection:
    response = None
    requests = []

    def __init__(self, host, timeout):
        self.host, self.timeout = host, timeout

    def request(self, method, path, headers):
        self.requests.append((method, path, headers))

    def getresponse(self):
        return self.response

    def close(self):
        pass


def settings(**kwargs):
    return BackupSettings("webmonitorforintern", "sentinel-backups", **kwargs)


def dump_executable(tmp_path, payload=b"abcdefghij", exit_code=0):
    path = tmp_path / "fake-pg-dump"
    path.write_text(f"#!/bin/sh\nprintf '%s' '{payload.decode()}'\nexit {exit_code}\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return str(path)


def test_pg_dump_command_uses_stdout_not_dash_file(tmp_path, monkeypatch):
    seen = []

    class Process:
        stdout = None
        stderr = io.BytesIO()

        def poll(self): return 0
        def wait(self): return 0

    def popen(command, **kwargs):
        seen.append(command)
        return Process()

    monkeypatch.setattr("scripts.ops.backup_postgres.subprocess.Popen", popen)
    monkeypatch.setattr("scripts.ops.backup_postgres._dump_tool_version", lambda command: "test")
    with pytest.raises(AssertionError):
        backup_postgres(settings(), "dsn", dump_executable(tmp_path), uploader=FakeUploader())
    assert "--file" not in seen[0]
    assert "-" not in seen[0]


def test_settings_are_azure_service_principal(monkeypatch):
    monkeypatch.setenv("BACKUP_STORAGE_BACKEND", "azure_blob")
    monkeypatch.setenv("BACKUP_AZURE_ACCOUNT", "webmonitorforintern")
    monkeypatch.setenv("BACKUP_AZURE_CONTAINER", "sentinel-backups")
    monkeypatch.setenv("AZURE_TENANT_ID", "tenant")
    monkeypatch.setenv("AZURE_CLIENT_ID", "client")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "secret")
    config = BackupSettings.from_env()
    assert config.auth == "service_principal"


def test_backup_set_uses_one_id_and_publishes_set_manifest_last(monkeypatch):
    calls = []
    set_id = "set-123"

    def postgres_backup(**kwargs):
        calls.append(("postgres", kwargs["backup_set_id"]))
        return {"backup_id": set_id, "object_key": "sentinelhub/postgres/set-123/database.dump",
                "bytes": 10, "sha256": "pg", "status": "completed"}

    def clickhouse_backup(**kwargs):
        calls.append(("clickhouse", kwargs["backup_set_id"]))
        return {"backup_id": set_id, "object_key": "sentinelhub/clickhouse/set-123/database.zip",
                "bytes": 5, "sha256": "ch", "status": "completed"}

    class SetUploader:
        def __init__(self, settings):
            self.uploads = []

        def put_bytes(self, key, data, content_type="application/json"):
            self.uploads.append((key, json.loads(data)))
            assert calls == [("postgres", set_id), ("clickhouse", set_id)]

    uploader = SetUploader(settings())
    result = backup_set(settings(), "dsn", "ipintel", backup_set_id=set_id,
                        postgres_backup=postgres_backup, clickhouse_backup=clickhouse_backup,
                        uploader_factory=lambda settings: uploader)
    assert calls == [("postgres", set_id), ("clickhouse", set_id)]
    assert result["backup_set_id"] == set_id
    assert result["status"] == "completed"
    assert result["postgres"]["sha256"] == "pg"
    assert result["clickhouse"]["sha256"] == "ch"


def test_backup_set_failure_never_publishes_set_manifest():
    published = []

    def postgres_backup(**kwargs):
        return {"backup_id": "set-123", "object_key": "pg", "bytes": 1, "sha256": "pg", "status": "completed"}

    def clickhouse_backup(**kwargs):
        raise RuntimeError("clickhouse failure")

    class SetUploader:
        def __init__(self, settings):
            pass

        def put_bytes(self, key, data, content_type="application/json"):
            published.append(key)

    with pytest.raises(RuntimeError, match="clickhouse failure"):
        backup_set(settings(), "dsn", "ipintel", backup_set_id="set-123",
                   postgres_backup=postgres_backup, clickhouse_backup=clickhouse_backup,
                   uploader_factory=SetUploader)
    assert not published


def _retention_manifest(set_id, completed_at, status="completed"):
    component = lambda name: {
        "backup_id": set_id, "object_key": f"sentinelhub/{name}/{set_id}/database.bin",
        "manifest_object_key": f"sentinelhub/manifests/{name}/{set_id}.json",
        "bytes": 1, "sha256": "0" * 64, "status": "completed",
    }
    return {
        "schema_version": 1, "backup_set_id": set_id, "completed_at": completed_at,
        "status": status, "postgres": component("postgres"), "clickhouse": component("clickhouse"),
    }


def test_retention_union_preserves_monthly_and_excludes_unfinished_periods():
    as_of = datetime(2026, 8, 29, 12, tzinfo=timezone.utc)
    manifests = [
        _retention_manifest("today", "2026-08-29T01:00:00+00:00"),
        _retention_manifest("same-day-newer", "2026-08-29T02:00:00+00:00"),
        _retention_manifest("july-monthly", "2026-07-31T01:00:00+00:00"),
        _retention_manifest("june-monthly", "2026-06-30T01:00:00+00:00"),
        _retention_manifest("may-monthly", "2026-05-31T01:00:00+00:00"),
        _retention_manifest("old", "2026-04-14T01:00:00+00:00"),
        _retention_manifest("failed", "2026-08-28T01:00:00+00:00", status="failed"),
    ]
    decisions = {item.backup_set_id: item for item in plan_retention(
        manifests, as_of=as_of, daily_days=2, weekly_weeks=1, monthly_months=3
    )}
    assert decisions["same-day-newer"].decision == "KEEP"
    assert "daily" in decisions["same-day-newer"].reasons
    assert decisions["july-monthly"].decision == "KEEP"
    assert "monthly" in decisions["july-monthly"].reasons
    assert decisions["old"].decision == "DELETE_CANDIDATE"
    assert decisions["failed"].decision == "PROTECTED"
    assert "weekly" not in decisions["today"].reasons
    assert "monthly" not in decisions["today"].reasons


def test_retention_plan_is_deterministic():
    manifests = [_retention_manifest("one", "2026-07-31T01:00:00+00:00")]
    as_of = datetime(2026, 8, 29, tzinfo=timezone.utc)
    first = plan_retention(manifests, as_of=as_of)
    second = plan_retention(manifests, as_of=as_of)
    assert [item.as_dict() for item in first] == [item.as_dict() for item in second]


def test_sdk_blob_transport_stages_ordered_blocks_and_commits():
    pytest.importorskip("azure.core.pipeline.policies", reason="Azure SDK is required for SDK transport test")
    service = FakeService()
    uploader = AzureBlobUploader(settings(), blob_service=service, credential=object())
    first, second = base64.b64encode(b"00000001").decode(), base64.b64encode(b"00000002").decode()
    uploader.put_block("x.dump", first, b"first")
    uploader.put_block("x.dump", second, b"last")
    uploader.put_block_list("x.dump", [first, second])
    blob = service.container.blobs["x.dump"]
    assert blob.blocks == [(first, b"first"), (second, b"last")]
    assert blob.commits == [[first, second]]


def test_sdk_rejects_empty_block():
    pytest.importorskip("azure.core.pipeline.policies", reason="Azure SDK is required for SDK transport test")
    uploader = AzureBlobUploader(settings(), blob_service=FakeService(), credential=object())
    with pytest.raises(ValueError, match="must not be empty"):
        uploader.put_block("x.dump", "MDAwMDAwMDE=", b"")


def test_postgres_streams_hashes_and_commits_final_partial_block(tmp_path):
    payload = b"abcdefghij"
    uploader = FakeUploader()
    result = backup_postgres(settings(part_size=4), "postgresql://redacted", dump_executable(tmp_path, payload), uploader=uploader)
    assert [block[2] for block in uploader.blocks] == [b"abcd", b"efgh", b"ij"]
    assert [block[1] for block in uploader.blocks] == [base64.b64encode(f"{n:08d}".encode()).decode() for n in (1, 2, 3)]
    assert len(uploader.commits) == 1
    assert result["bytes"] == len(payload)
    assert result["sha256"] == hashlib.sha256(payload).hexdigest()
    assert result["block_count"] == 3
    assert not list(tmp_path.glob("*.dump"))


def test_block_failure_never_commits(tmp_path):
    uploader = FakeUploader(fail_block=True)
    with pytest.raises(RuntimeError, match="block failure"):
        backup_postgres(settings(), "dsn", dump_executable(tmp_path), uploader=uploader)
    assert not uploader.commits


def test_pg_dump_failure_never_commits(tmp_path):
    uploader = FakeUploader()
    with pytest.raises(RuntimeError, match="pg_dump failed with exit 2"):
        backup_postgres(settings(), "dsn", dump_executable(tmp_path, b"partial", 2), uploader=uploader)
    assert not uploader.commits


def test_block_list_failure_is_reported(tmp_path):
    uploader = FakeUploader(fail_commit=True)
    with pytest.raises(RuntimeError, match="commit failure"):
        backup_postgres(settings(), "dsn", dump_executable(tmp_path), uploader=uploader)
    assert not uploader.manifests


def test_clickhouse_native_file_backup_uploads_verifies_and_cleans(tmp_path):
    artifact = tmp_path / "native.zip"
    directory = tmp_path / "artifact-dir"
    uploader = FakeClickHouseUploader(remote_size=len(b"native-clickhouse-backup"))
    client = FakeClickHouseClient(artifact)
    result = backup_clickhouse(settings(), "ipintel", client=client, uploader=uploader,
                               artifact_factory=lambda: (directory, artifact),
                               verifier=lambda settings, key: (len(b"native-clickhouse-backup"), hashlib.sha256(b"native-clickhouse-backup").hexdigest()))
    assert client.commands[0].startswith("BACKUP DATABASE `ipintel` TO File('")
    assert "CSV" not in client.commands[0]
    assert "JSON" not in client.commands[0]
    assert result["backup_type"] == "clickhouse_native"
    assert result["bytes"] == len(b"native-clickhouse-backup")
    assert result["status"] == "completed"
    assert not directory.exists()
    assert len(uploader.manifests) == 1


def test_clickhouse_native_backup_failure_does_not_upload_or_cleanup(tmp_path):
    artifact = tmp_path / "native.zip"
    directory = tmp_path / "artifact-dir"
    directory.mkdir()
    client = FakeClickHouseClient(artifact, fail=True)
    uploader = FakeClickHouseUploader()
    with pytest.raises(RuntimeError, match="native BACKUP TO File failed"):
        backup_clickhouse(settings(), "ipintel", client=client, uploader=uploader,
                          artifact_factory=lambda: (directory, artifact))
    assert not uploader.uploads
    assert directory.exists()


def test_clickhouse_upload_or_remote_verify_failure_preserves_artifact(tmp_path):
    artifact = tmp_path / "native.zip"
    directory = tmp_path / "artifact-dir"
    directory.mkdir()
    client = FakeClickHouseClient(artifact)
    uploader = FakeClickHouseUploader(remote_size=1, fail=False)
    with pytest.raises(RuntimeError, match="size verification failed"):
        backup_clickhouse(settings(), "ipintel", client=client, uploader=uploader,
                          artifact_factory=lambda: (directory, artifact),
                          verifier=lambda settings, key: (1, hashlib.sha256(b"native-clickhouse-backup").hexdigest()))
    assert directory.exists()


def test_clickhouse_sha_verification_failure_preserves_artifact(tmp_path):
    artifact = tmp_path / "native.zip"
    directory = tmp_path / "artifact-dir"
    directory.mkdir()
    client = FakeClickHouseClient(artifact)
    uploader = FakeClickHouseUploader()
    with pytest.raises(RuntimeError, match="SHA-256 verification failed"):
        backup_clickhouse(settings(), "ipintel", client=client, uploader=uploader,
                          artifact_factory=lambda: (directory, artifact),
                          verifier=lambda settings, key: (len(b"native-clickhouse-backup"), "0" * 64))
    assert directory.exists()


def test_clickhouse_default_artifact_is_temporary(tmp_path, monkeypatch):
    monkeypatch.delenv("CLICKHOUSE_BACKUP_TEMP_DIR", raising=False)
    from scripts.ops.backup_clickhouse import _artifact_path
    directory, artifact = _artifact_path()
    try:
        assert directory.parent != tmp_path
        assert directory.name.startswith("phase10a3-")
        assert artifact.parent == directory
    finally:
        directory.rmdir()


def test_rest_verifier_streams_matching_blob(monkeypatch):
    payload = b"remote-native-backup"
    FakeHttpsConnection.response = FakeHttpResponse(200, payload)
    FakeHttpsConnection.requests = []
    monkeypatch.setattr("scripts.ops.backup_clickhouse.http.client.HTTPSConnection", FakeHttpsConnection)
    monkeypatch.setattr("scripts.ops.backup_clickhouse._credential", lambda settings: type("Credential", (), {"get_token": lambda self, scope: type("Token", (), {"token": "redacted-token"})()})())
    size, digest = _verify_remote_blob(settings(), "sentinelhub/clickhouse/id/database.zip")
    assert size == len(payload)
    assert digest == hashlib.sha256(payload).hexdigest()
    assert FakeHttpsConnection.requests[0][2]["Authorization"] == "Bearer redacted-token"


@pytest.mark.parametrize("status", [401, 403, 404])
def test_rest_verifier_rejects_http_error(monkeypatch, status):
    FakeHttpsConnection.response = FakeHttpResponse(status, b"")
    monkeypatch.setattr("scripts.ops.backup_clickhouse.http.client.HTTPSConnection", FakeHttpsConnection)
    monkeypatch.setattr("scripts.ops.backup_clickhouse._credential", lambda settings: type("Credential", (), {"get_token": lambda self, scope: type("Token", (), {"token": "secret"})()})())
    with pytest.raises(RuntimeError, match=f"HTTP {status}"):
        _verify_remote_blob(settings(), "blob")


def test_rest_verifier_rejects_content_length_mismatch(monkeypatch):
    FakeHttpsConnection.response = FakeHttpResponse(200, b"payload", content_length=99)
    monkeypatch.setattr("scripts.ops.backup_clickhouse.http.client.HTTPSConnection", FakeHttpsConnection)
    monkeypatch.setattr("scripts.ops.backup_clickhouse._credential", lambda settings: type("Credential", (), {"get_token": lambda self, scope: type("Token", (), {"token": "secret"})()})())
    with pytest.raises(RuntimeError, match="Content-Length mismatch"):
        _verify_remote_blob(settings(), "blob")
