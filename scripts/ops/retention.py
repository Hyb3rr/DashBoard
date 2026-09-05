"""Plan manifest-driven backup retention without deleting any Azure object."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
import json
import os
from urllib.parse import quote, urlsplit
import http.client
import xml.etree.ElementTree as ET

from app.config.backup import BackupSettings
from scripts.ops.backup_postgres import _credential


@dataclass(frozen=True)
class RetentionDecision:
    backup_set_id: str
    decision: str
    reasons: tuple[str, ...]
    completed_at: str | None
    object_keys: tuple[str, ...]

    def as_dict(self) -> dict:
        return {
            "backup_set_id": self.backup_set_id,
            "decision": self.decision,
            "reasons": list(self.reasons),
            "completed_at": self.completed_at,
            "object_keys": list(self.object_keys),
        }


def _timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _valid_completed_set(manifest: dict, as_of: datetime) -> bool:
    if manifest.get("status") != "completed" or not manifest.get("backup_set_id"):
        return False
    try:
        completed_at = _timestamp(manifest["completed_at"])
    except (KeyError, TypeError, ValueError):
        return False
    if completed_at > as_of + timedelta(minutes=5):
        return False
    backup_set_id = manifest["backup_set_id"]
    for name in ("postgres", "clickhouse"):
        component = manifest.get(name)
        if not isinstance(component, dict):
            return False
        if component.get("status") != "completed":
            return False
        if component.get("backup_id") != backup_set_id:
            return False
        if not component.get("object_key") or not component.get("manifest_object_key"):
            return False
        if not isinstance(component.get("bytes"), int) or component["bytes"] <= 0:
            return False
        if not isinstance(component.get("sha256"), str) or len(component["sha256"]) != 64:
            return False
    return True


def _component_keys(manifest: dict) -> tuple[str, ...]:
    keys = [manifest["_set_manifest_object_key"]] if manifest.get("_set_manifest_object_key") else []
    for name in ("postgres", "clickhouse"):
        component = manifest[name]
        keys.extend((component["object_key"], component["manifest_object_key"]))
    return tuple(keys)


def plan_retention(manifests: list[dict], as_of: datetime | None = None,
                   daily_days: int = 7, weekly_weeks: int = 4,
                   monthly_months: int = 3) -> list[RetentionDecision]:
    """Return a deterministic plan. This function has no Azure mutation path."""
    as_of = as_of or datetime.now(timezone.utc)
    if as_of.tzinfo is None:
        as_of = as_of.replace(tzinfo=timezone.utc)
    valid, invalid = [], []
    for manifest in manifests:
        if not _valid_completed_set(manifest, as_of):
            invalid.append(manifest)
            continue
        valid.append((manifest, _timestamp(manifest["completed_at"])))
    valid.sort(key=lambda item: (item[1], item[0]["backup_set_id"]), reverse=True)

    daily_by_day: dict[date, tuple[dict, datetime]] = {}
    weekly_by_week: dict[tuple[int, int], tuple[dict, datetime]] = {}
    monthly_by_month: dict[tuple[int, int], tuple[dict, datetime]] = {}
    current_week = as_of.date().isocalendar()[:2]
    current_month = (as_of.year, as_of.month)
    for manifest, completed_at in valid:
        day = completed_at.date()
        daily_by_day.setdefault(day, (manifest, completed_at))
        week = completed_at.date().isocalendar()[:2]
        if week != current_week:
            weekly_by_week.setdefault(week, (manifest, completed_at))
        month = (completed_at.year, completed_at.month)
        if month != current_month:
            monthly_by_month.setdefault(month, (manifest, completed_at))

    keep_reasons: dict[str, set[str]] = {}
    for label, records in (
        ("daily", sorted(daily_by_day.items(), reverse=True)[:daily_days]),
        ("weekly", sorted(weekly_by_week.items(), reverse=True)[:weekly_weeks]),
        ("monthly", sorted(monthly_by_month.items(), reverse=True)[:monthly_months]),
    ):
        for _, (manifest, _) in records:
            keep_reasons.setdefault(manifest["backup_set_id"], set()).add(label)

    decisions = []
    for manifest, _ in valid:
        backup_set_id = manifest["backup_set_id"]
        reasons = tuple(sorted(keep_reasons.get(backup_set_id, set())))
        decisions.append(RetentionDecision(
            backup_set_id=backup_set_id,
            decision="KEEP" if reasons else "DELETE_CANDIDATE",
            reasons=reasons or ("expired",),
            completed_at=manifest["completed_at"],
            object_keys=_component_keys(manifest),
        ))
    for manifest in invalid:
        decisions.append(RetentionDecision(
            backup_set_id=str(manifest.get("backup_set_id") or "unknown"),
            decision="PROTECTED",
            reasons=("invalid_or_incomplete_manifest",),
            completed_at=manifest.get("completed_at"),
            object_keys=(),
        ))
    return sorted(decisions, key=lambda item: (item.completed_at or "", item.backup_set_id), reverse=True)


def _request(settings: BackupSettings, method: str, path: str) -> bytes:
    endpoint = urlsplit(settings.endpoint)
    token = _credential(settings).get_token("https://storage.azure.com/.default").token
    connection = http.client.HTTPSConnection(endpoint.netloc, timeout=30)
    try:
        connection.request(method, path, headers={
            "Authorization": f"Bearer {token}",
            "x-ms-version": "2023-11-03",
        })
        response = connection.getresponse()
        body = response.read()
        if response.status != 200:
            raise RuntimeError(f"Azure retention inventory request failed with HTTP {response.status}")
        return body
    finally:
        connection.close()


def load_set_manifests(settings: BackupSettings) -> list[dict]:
    """Read set manifests through Blob REST; never sends PUT/DELETE."""
    prefix = f"{settings.prefix}/manifests/sets/"
    marker = ""
    manifests = []
    while True:
        query = f"restype=container&comp=list&prefix={quote(prefix, safe='/')}&maxresults=5000"
        if marker:
            query += f"&marker={quote(marker, safe='')}"
        listing = ET.fromstring(_request(settings, "GET", f"/{quote(settings.container, safe='/')}?{query}"))
        names = [node.findtext("./{*}Name") for node in listing.findall(".//{*}Blob")]
        for name in filter(None, names):
            if not name.endswith(".json"):
                continue
            body = _request(settings, "GET", f"/{quote(settings.container, safe='/')}/{quote(name, safe='/')}")
            try:
                manifest = json.loads(body)
            except json.JSONDecodeError:
                manifest = {"backup_set_id": name, "status": "invalid"}
            manifest["_set_manifest_object_key"] = name
            manifests.append(manifest)
        marker = listing.findtext("./{*}NextMarker") or ""
        if not marker:
            break
    return manifests


def main() -> None:
    parser = argparse.ArgumentParser(description="Plan Azure backup retention without deleting objects")
    parser.add_argument("--as-of", help="UTC ISO timestamp for deterministic planning")
    args = parser.parse_args()
    settings = BackupSettings.from_env()
    as_of = _timestamp(args.as_of) if args.as_of else None
    manifests = load_set_manifests(settings)
    decisions = plan_retention(manifests, as_of=as_of)
    print(json.dumps({
        "mode": "dry_run",
        "delete_api_called": False,
        "policy": {"daily_days": 7, "weekly_weeks": 4, "monthly_months": 3},
        "manifest_count": len(manifests),
        "decisions": [decision.as_dict() for decision in decisions],
    }, indent=2))


if __name__ == "__main__":
    main()
