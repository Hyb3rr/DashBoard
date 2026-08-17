"""Single, failure-isolated updater for local privacy and threat snapshots."""
from __future__ import annotations

import fcntl
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ..config.settings import DATA_DIR, DB_PATH
from .db import connect
from ..providers import vpn_az0, cidr_lists, device_browser_info, firehol, cloudflare, global_geo

INTERVALS = {"az0_vpn": 24, "x4b_vpn": 24, "x4b_datacenter": 24, "cloudflare_datacenter": 24, "device_browser_proxy": 6}
DEFAULT_X4B_URLS = {
    "x4b_vpn": "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt",
    "x4b_datacenter": "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt",
}


def _positive_int(name: str, default: int, maximum: int = 32) -> int:
    try:
        return max(1, min(int(os.getenv(name, str(default))), maximum))
    except (TypeError, ValueError):
        return default

def _due(row, now, hours):
    if not row or not row["last_run_at"]: return True
    if row["last_status"] == "failed": return True
    try: return now - datetime.fromisoformat(row["last_run_at"]) >= timedelta(hours=hours)
    except ValueError: return True

def _status(conn, name, now, result):
    conn.execute("""INSERT INTO intel_source_status(source_name,last_run_at,last_status,last_error,records_upserted,metadata_json)
      VALUES(?,?,?,?,?,?) ON CONFLICT(source_name) DO UPDATE SET last_run_at=excluded.last_run_at,last_status=excluded.last_status,last_error=excluded.last_error,records_upserted=excluded.records_upserted,metadata_json=excluded.metadata_json""",
      (name, now.isoformat(), result.get("status", "failed"), result.get("error"), int(result.get("records_upserted", 0)), json.dumps(result, default=str)))


def _run_provider(factory):
    """Run one provider with a connection owned by its worker thread."""
    conn = connect()
    try:
        result = factory(conn)
        conn.commit()
        return result
    except Exception as exc:
        conn.rollback()
        return {"status": "failed", "error": f"{type(exc).__name__}: {exc}", "records_upserted": 0}
    finally:
        conn.close()

def run_due_sources(now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    lock_path = Path(os.getenv("INTEL_UPDATE_LOCK_PATH", str(DATA_DIR / "intel_updater.lock")))
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("w") as handle:
        try: fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: return {"status":"locked"}
        conn = connect(); report = {}
        try:
            rows={r["source_name"]:r for r in conn.execute("SELECT * FROM intel_source_status")}
            jobs=[("az0_vpn", INTERVALS["az0_vpn"], lambda c: vpn_az0.refresh(c)),
              ("x4b_vpn",24,lambda c: _x4b(c,"x4b_vpn","vpn",os.getenv("X4B_VPN_LIST_URL") or DEFAULT_X4B_URLS["x4b_vpn"])),
              ("x4b_datacenter",24,lambda c: _x4b(c,"x4b_datacenter","datacenter",os.getenv("X4B_DATACENTER_LIST_URL") or DEFAULT_X4B_URLS["x4b_datacenter"])),
              ("cloudflare_datacenter",24,lambda c: cloudflare.refresh(c)),
              ("device_browser_proxy",6,lambda c: device_browser_info.refresh(c))]
            rir_urls = {
                "APNIC": os.getenv("RIR_APNIC_URL", "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest"),
                "RIPE": os.getenv("RIR_RIPE_URL", "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest"),
                "ARIN": os.getenv("RIR_ARIN_URL", "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest"),
                "LACNIC": os.getenv("RIR_LACNIC_URL", "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest"),
                "AFRINIC": os.getenv("RIR_AFRINIC_URL", "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest"),
            }
            if os.getenv("GEO_RIR_REFRESH_ENABLED", "true").lower() in {"1", "true", "yes", "on"}:
                for rir, url in rir_urls.items():
                    jobs.append((f"rir:{rir.lower()}", 24, lambda c, rir=rir, url=url: global_geo.refresh_rir(c, rir, url)))
            geofeeds = [item.strip().split("=", 1) for item in os.getenv("GEOFEED_SOURCES", "").split(",") if "=" in item]
            for name, url in geofeeds:
                jobs.append((f"geofeed:{name}", 168, lambda c, name=name, url=url: global_geo.refresh_geofeed(c, name, url)))
            selected=os.getenv("FIREHOL_LISTS", ",".join(firehol.DEFAULT_LISTS)).split(",")
            for name in selected:
                name=name.strip()
                if name: jobs.append((f"firehol:{name}", 24, lambda c, name=name: firehol.refresh_list(c,name)))
            due = [(name, task) for name, hours, task in jobs if _due(rows.get(name), now, hours)]
            for name, hours, _task in jobs:
                if not _due(rows.get(name), now, hours):
                    report[name] = {"status": "not_due"}
            with ThreadPoolExecutor(max_workers=_positive_int("INTEL_UPDATE_CONCURRENCY", 6, 8)) as pool:
                futures = {pool.submit(_run_provider, task): name for name, task in due}
                for future in as_completed(futures):
                    name = futures[future]
                    result = future.result()
                    _status(conn, name, now, result)
                    report[name] = result
                    conn.commit()
            conn.commit(); return {"status":"completed","sources":report}
        finally: conn.close()

def _x4b(conn, source, kind, url):
    if not url: return {"status":"not_configured","records_upserted":0}
    return cidr_lists.refresh_cidr_source(conn,source,url,kind)

if __name__ == "__main__":
    print(json.dumps(run_due_sources(), indent=2, default=str))
