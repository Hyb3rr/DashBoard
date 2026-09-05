"""Single, failure-isolated updater for local privacy and threat snapshots."""
from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone

from ..db import postgres
from ..providers import pg_intel
from psycopg.types.json import Jsonb

INTERVALS = {"az0_vpn": 24, "x4b_vpn": 24, "x4b_datacenter": 24, "cloudflare_datacenter": 24, "device_browser_proxy": 6}
DEFAULT_X4B_URLS = {
    "x4b_vpn": "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt",
    "x4b_datacenter": "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt",
}
INTEL_REFRESH_LOCK = "ip-intelligence:run-due-sources"


def _positive_int(name: str, default: int, maximum: int = 32) -> int:
    try:
        return max(1, min(int(os.getenv(name, str(default))), maximum))
    except (TypeError, ValueError):
        return default

def _due(row, now, hours):
    if not row or not row["last_run_at"]:
        return True
    if row["last_status"] in {"failed", "unavailable"}:
        return True
    try:
        last = row["last_run_at"]
        if isinstance(last, str):
            last = datetime.fromisoformat(last)
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        return now - last >= timedelta(hours=hours)
    except (TypeError, ValueError):
        return True


def _run_provider_pg(factory, source_name, now):
    """Run a normalized provider against one PostgreSQL transaction."""
    conn = postgres.connect()
    try:
        result = factory(conn)
        _status_pg(conn, source_name, now, result)
        conn.commit()
        return result
    except Exception as exc:
        conn.rollback()
        result = {"status": "failed", "error": f"{type(exc).__name__}: {exc}", "records_upserted": 0}
        try:
            status_conn = postgres.connect()
            try:
                _status_pg(status_conn, source_name, now, result)
                status_conn.commit()
            except Exception:
                status_conn.rollback()
            finally:
                status_conn.close()
        except Exception:
            pass
        return result
    finally:
        conn.close()


def _status_pg(conn, name, now, result):
    conn.execute("""INSERT INTO intel_source_status
      (source_name,last_run_at,last_status,last_error,records_upserted,metadata)
      VALUES(%s,%s,%s,%s,%s,%s)
      ON CONFLICT(source_name) DO UPDATE SET last_run_at=excluded.last_run_at,
       last_status=excluded.last_status,last_error=excluded.last_error,
       records_upserted=excluded.records_upserted,metadata=excluded.metadata""",
      (name, now, result.get("status", "failed"), result.get("error"),
       int(result.get("records_upserted", 0)), Jsonb(result)))


def run_due_sources(now: datetime | None = None) -> dict:
    """PostgreSQL-only intelligence updater."""
    now = now or datetime.now(timezone.utc)
    status_conn = postgres.connect()
    lock_row = status_conn.execute(
        "SELECT pg_try_advisory_lock(hashtextextended(%s, 0)) AS acquired",
        (INTEL_REFRESH_LOCK,),
    ).fetchone()
    if not lock_row or not lock_row["acquired"]:
        status_conn.close()
        return {"status": "locked", "backend": "postgres"}
    try:
        rows = {r["source_name"]: r for r in status_conn.execute("SELECT * FROM intel_source_status")}
        jobs = [
            ("az0_vpn", 24, lambda c: pg_intel.refresh_az0(c)),
            ("x4b_vpn", 24, lambda c: pg_intel.refresh_cidr(c, "x4b_vpn", os.getenv("X4B_VPN_LIST_URL") or DEFAULT_X4B_URLS["x4b_vpn"], "vpn")),
            ("x4b_datacenter", 24, lambda c: pg_intel.refresh_cidr(c, "x4b_datacenter", os.getenv("X4B_DATACENTER_LIST_URL") or DEFAULT_X4B_URLS["x4b_datacenter"], "datacenter")),
            ("cloudflare_datacenter", 24, lambda c: pg_intel.refresh_cloudflare(c)),
            ("device_browser_proxy", 6, lambda c: pg_intel.refresh_device_browser(c)),
            ("sapics_releases", _positive_int("SAPICS_REFRESH_HOURS", 24, 8760),
             lambda c: __import__("app.services.sapics_updater", fromlist=["refresh"]).refresh()),
        ]
        rir_urls = {
            "APNIC": os.getenv("RIR_APNIC_URL", "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest"),
            "RIPE": os.getenv("RIR_RIPE_URL", "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest"),
            "ARIN": os.getenv("RIR_ARIN_URL", "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest"),
            "LACNIC": os.getenv("RIR_LACNIC_URL", "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest"),
            "AFRINIC": os.getenv("RIR_AFRINIC_URL", "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest"),
        }
        if os.getenv("GEO_RIR_REFRESH_ENABLED", "true").lower() in {"1", "true", "yes", "on"}:
            for rir, url in rir_urls.items():
                jobs.append((f"rir:{rir.lower()}", 24, lambda c, rir=rir, url=url: pg_intel.refresh_rir(c, rir, url)))
        for item in os.getenv("GEOFEED_SOURCES", "").split(","):
            if "=" in item:
                name, url = item.strip().split("=", 1)
                jobs.append((f"geofeed:{name}", 168, lambda c, name=name, url=url: pg_intel.refresh_geofeed(c, name, url)))
        jobs.append(("geofeed:geolocatemuch", 24, lambda c: pg_intel.refresh_geofeed(
            c, "geolocatemuch", os.getenv("GEOLOCATEMUCH_GEOFEED_URL", "https://geolocatemuch.com/geofeeds/validated-all.csv"))))
        
        # FireHOL lists
        from ..providers import firehol
        selected = os.getenv("FIREHOL_LISTS", ",".join(firehol.DEFAULT_LISTS)).split(",")
        for name in selected:
            name = name.strip()
            if name:
                jobs.append((f"firehol:{name}", 24, lambda c, name=name: pg_intel.refresh_firehol(c, name)))
        due = [(name, task) for name, hours, task in jobs if _due(rows.get(name), now, hours)]
        report = {name: {"status": "not_due"} for name, hours, _ in jobs if not _due(rows.get(name), now, hours)}
        with ThreadPoolExecutor(max_workers=_positive_int("INTEL_UPDATE_CONCURRENCY", 6, 8)) as pool:
            futures = {pool.submit(_run_provider_pg, task, name, now): name for name, task in due}
            for future in as_completed(futures):
                name, result = futures[future], future.result()
                report[name] = result
        return {"status": "completed", "backend": "postgres", "sources": report}
    finally:
        status_conn.execute(
            "SELECT pg_advisory_unlock(hashtextextended(%s, 0))",
            (INTEL_REFRESH_LOCK,),
        )
        status_conn.close()


if __name__ == "__main__":
    print(json.dumps(run_due_sources(), indent=2, default=str))
