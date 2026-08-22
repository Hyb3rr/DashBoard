"""Periodic, shadow-only rare-path evidence generation."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os

from ..config import settings
from ..core import metrics
from ..db import clickhouse
from ..db.repositories import ObservationRepository


def rarity_score(row: dict, baseline_buckets: int = 168, now: datetime | None = None) -> int:
    """Score evidence only; never maps to BAD/WATCH classification."""
    now = now or datetime.now(timezone.utc)
    population = int(row.get("total_ips") or 0)
    path_ips = int(row.get("path_ips") or 0)
    buckets = int(row.get("temporal_buckets") or 0)
    population_points = 40 if path_ips <= 1 else max(0, round(40 * (1 - path_ips / max(population, 1))))
    temporal_points = max(0, round(30 * (1 - buckets / max(baseline_buckets, 1))))
    try:
        first_seen = datetime.fromisoformat(str(row["first_seen"]).replace("Z", "+00:00"))
        age = now - first_seen
    except (KeyError, TypeError, ValueError):
        age = timedelta.max
    newness_points = 30 if age <= timedelta(hours=1) else 15 if age <= timedelta(hours=24) else 0
    return max(0, min(100, population_points + temporal_points + newness_points))


def run_shadow(now: datetime | None = None) -> tuple[int, list[str]]:
    """Scan one rolling window and persist supporting evidence in PostgreSQL."""
    finish = metrics.timed("rare_path.batch_ms")
    now = now or datetime.now(timezone.utc)
    try:
        start = now - timedelta(days=7)
        rows = clickhouse.rare_path_baseline(start, now, settings.DATASET_LIVE_ID)
        by_ip: dict[str, list[dict]] = {}
        for row in rows:
            by_ip.setdefault(row["ip"], []).append({
                "source": "rare_path_shadow",
                "path": row["path"],
                "observed": int(row["path_requests"]),
                "baseline": {"days": 7, "distinct_ips": int(row["path_ips"]), "total_ips": int(row["total_ips"]), "temporal_buckets": int(row["temporal_buckets"])},
                "first_seen": row["first_seen"], "last_seen": row["last_seen"],
                "rarity_score": rarity_score(row, now=now),
                "explanation": "Supporting evidence only; rarity alone does not establish malicious intent.",
                "freshness": now.isoformat(),
            })
        for evidence in by_ip.values():
            evidence.sort(key=lambda item: (-item["rarity_score"], item["path"]))
        changed_ips = ObservationRepository().upsert_rare_path_evidence(by_ip, settings.DATASET_LIVE_ID)
        count = sum(len(items) for items in by_ip.values())
        metrics.gauge("rare_path.evidence_count", count)
        metrics.increment("rare_path.batches")
        return count, changed_ips
    except Exception:
        metrics.increment("rare_path.errors")
        raise
    finally:
        finish()


async def periodic_shadow(stop_event, on_changed=None) -> None:
    """Run outside ingest flush path at a bounded periodic cadence."""
    import asyncio

    interval = max(60, int(os.getenv("RARE_PATH_INTERVAL_SECONDS", "300")))
    while not stop_event.is_set():
        await asyncio.sleep(interval)
        if stop_event.is_set():
            break
        try:
            count, changed_ips = await asyncio.to_thread(run_shadow)
            if changed_ips and on_changed:
                await on_changed(changed_ips)
        except Exception:
            pass
