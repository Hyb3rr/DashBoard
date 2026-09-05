"""Validate retention semantics using tiny Azure objects in a test prefix."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import argparse
import hashlib
import json
import secrets
from urllib.parse import quote, urlsplit
import http.client

from app.config.backup import BackupSettings
from scripts.ops.backup_postgres import AzureBlobUploader, _credential
from scripts.ops.retention import load_set_manifests, plan_retention


AS_OF = datetime(2026, 8, 29, 12, tzinfo=timezone.utc)


def _manifest(prefix: str, set_id: str, completed_at: str, status: str = "completed") -> tuple[dict, list[str]]:
    keys = []
    components = {}
    for name, suffix in (("postgres", "database.dump"), ("clickhouse", "database.zip")):
        object_key = f"{prefix}/{name}/{set_id}/{suffix}"
        component_manifest_key = f"{prefix}/manifests/{name}/{set_id}.json"
        keys.extend((object_key, component_manifest_key))
        components[name] = {
            "backup_id": set_id,
            "object_key": object_key,
            "manifest_object_key": component_manifest_key,
            "bytes": 1,
            "sha256": hashlib.sha256(b"x").hexdigest(),
            "status": "completed",
        }
    manifest = {
        "schema_version": 1,
        "backup_set_id": set_id,
        "completed_at": completed_at,
        "status": status,
        **components,
    }
    set_key = f"{prefix}/manifests/sets/{set_id}.json"
    keys.append(set_key)
    return manifest, keys


def _put(uploader: AzureBlobUploader, key: str, body: bytes) -> None:
    uploader.put_bytes(key, body, content_type="application/json")


def _delete(settings: BackupSettings, key: str) -> int:
    allowed = f"{settings.prefix}/"
    if not settings.prefix.startswith("sentinelhub/retention-test/") or not key.startswith(allowed):
        raise RuntimeError("synthetic cleanup refused outside retention-test prefix")
    endpoint = urlsplit(settings.endpoint)
    token = _credential(settings).get_token("https://storage.azure.com/.default").token
    connection = http.client.HTTPSConnection(endpoint.netloc, timeout=30)
    try:
        connection.request("DELETE", f"/{quote(settings.container, safe='/')}/{quote(key, safe='/')}", headers={
            "Authorization": f"Bearer {token}",
            "x-ms-version": "2023-11-03",
        })
        response = connection.getresponse()
        response.read()
        if response.status not in (202, 204):
            raise RuntimeError(f"synthetic cleanup failed with HTTP {response.status}")
        return response.status
    finally:
        connection.close()


def run_live(settings: BackupSettings) -> dict:
    run_id = secrets.token_hex(8)
    prefix = f"sentinelhub/retention-test/{run_id}"
    test_settings = replace(settings, prefix=prefix)
    uploader = AzureBlobUploader(test_settings)
    synthetic = []
    all_keys = []

    def add(set_id: str, timestamp: str, status: str = "completed", invalid: bool = False) -> None:
        manifest, keys = _manifest(prefix, set_id, timestamp, status)
        if invalid:
            manifest.pop("clickhouse")
        for key in keys:
            if key.endswith(".json"):
                if key.endswith(f"/sets/{set_id}.json"):
                    body = json.dumps(manifest).encode()
                else:
                    body = b"{}"
            else:
                body = b"x"
            _put(uploader, key, body)
        synthetic.append(manifest)
        all_keys.extend(keys)

    try:
        for day in ("23", "24", "25", "26", "27", "28", "29"):
            add(f"daily-{day}", f"2026-08-{day}T01:00:00+00:00")
        add("daily-29-old", "2026-08-29T00:30:00+00:00")
        for set_id, timestamp in (
            ("weekly-1", "2026-08-16T01:00:00+00:00"),
            ("weekly-2", "2026-08-09T01:00:00+00:00"),
            ("monthly-july", "2026-07-31T01:00:00+00:00"),
            ("monthly-june", "2026-06-30T01:00:00+00:00"),
            ("monthly-may", "2026-05-31T01:00:00+00:00"),
            ("expired", "2026-04-14T01:00:00+00:00"),
        ):
            add(set_id, timestamp)
        add("failed", "2026-08-28T03:00:00+00:00", status="failed")
        add("invalid", "2026-08-27T03:00:00+00:00", invalid=True)
        unknown_key = f"{prefix}/unknown-object.bin"
        _put(uploader, unknown_key, b"unknown")
        all_keys.append(unknown_key)

        loaded = load_set_manifests(test_settings)
        decisions = plan_retention(loaded, as_of=AS_OF)
        by_id = {item.backup_set_id: item for item in decisions}
        assert by_id["daily-29"].decision == "KEEP"
        assert by_id["daily-29-old"].decision == "DELETE_CANDIDATE"
        assert by_id["monthly-may"].decision == "KEEP"
        assert "monthly" in by_id["monthly-may"].reasons
        assert by_id["expired"].decision == "DELETE_CANDIDATE"
        assert by_id["failed"].decision == "PROTECTED"
        assert by_id["invalid"].decision == "PROTECTED"
        assert "weekly" in by_id["monthly-july"].reasons
        assert len([x for x in decisions if x.decision == "KEEP"]) == 12
        assert len([x for x in decisions if x.decision == "DELETE_CANDIDATE"]) == 2

        second = plan_retention(load_set_manifests(test_settings), as_of=AS_OF)
        assert [x.as_dict() for x in decisions] == [x.as_dict() for x in second]

        deleted = []
        for decision in decisions:
            if decision.decision == "DELETE_CANDIDATE":
                for key in decision.object_keys:
                    _delete(test_settings, key)
                    deleted.append(key)
        assert deleted
        assert all(key.startswith(prefix + "/") for key in deleted)
        return {
            "mode": "synthetic_live",
            "prefix": prefix,
            "manifest_count": len(loaded),
            "keep_count": 12,
            "delete_candidate_count": 2,
            "protected_count": 2,
            "unknown_object": "untouched_by_retention",
            "production_prefix_touched": False,
            "delete_scope": prefix,
        }
    finally:
        # Test teardown is limited to this run's synthetic prefix. It removes
        # keep/protected/unknown probes after assertions, never production data.
        for key in reversed(all_keys):
            try:
                _delete(test_settings, key)
            except Exception:
                pass


def main() -> None:
    parser = argparse.ArgumentParser(description="Run retention semantics against a tiny test prefix")
    parser.add_argument("--live", action="store_true", help="perform the isolated Azure test-prefix smoke test")
    args = parser.parse_args()
    if not args.live:
        raise SystemExit("refusing to run synthetic Azure mutation without --live")
    print(json.dumps(run_live(BackupSettings.from_env()), indent=2))


if __name__ == "__main__":
    main()
