"""Single, failure-isolated updater for local privacy and threat snapshots."""
from __future__ import annotations

import fcntl
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ..config.settings import DATA_DIR, DB_PATH
from .db import connect
from ..providers import vpn_az0, cidr_lists, device_browser_info, firehol, dnsbl, cloudflare, global_geo

INTERVALS = {"az0_vpn": 24, "x4b_vpn": 24, "x4b_datacenter": 24, "cloudflare_datacenter": 24, "device_browser_proxy": 6, "dnsbl_new_ips": 1}
DEFAULT_X4B_URLS = {
    "x4b_vpn": "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt",
    "x4b_datacenter": "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt",
}

def _due(row, now, hours):
    if not row or not row["last_run_at"]: return True
    if row["last_status"] == "failed": return True
    try: return now - datetime.fromisoformat(row["last_run_at"]) >= timedelta(hours=hours)
    except ValueError: return True

def _status(conn, name, now, result):
    conn.execute("""INSERT INTO intel_source_status(source_name,last_run_at,last_status,last_error,records_upserted,metadata_json)
      VALUES(?,?,?,?,?,?) ON CONFLICT(source_name) DO UPDATE SET last_run_at=excluded.last_run_at,last_status=excluded.last_status,last_error=excluded.last_error,records_upserted=excluded.records_upserted,metadata_json=excluded.metadata_json""",
      (name, now.isoformat(), result.get("status", "failed"), result.get("error"), int(result.get("records_upserted", 0)), json.dumps(result, default=str)))

def run_due_sources(now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    lock_path = Path(os.getenv("INTEL_UPDATE_LOCK_PATH", str(DATA_DIR / "intel_updater.lock")))
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("w") as handle:
        try: fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: return {"status":"locked"}
        conn=connect(); report={}
        try:
            rows={r["source_name"]:r for r in conn.execute("SELECT * FROM intel_source_status")}
            jobs=[("az0_vpn", INTERVALS["az0_vpn"], lambda: vpn_az0.refresh(conn)),
              ("x4b_vpn",24,lambda: _x4b(conn,"x4b_vpn","vpn",os.getenv("X4B_VPN_LIST_URL") or DEFAULT_X4B_URLS["x4b_vpn"])),
              ("x4b_datacenter",24,lambda: _x4b(conn,"x4b_datacenter","datacenter",os.getenv("X4B_DATACENTER_LIST_URL") or DEFAULT_X4B_URLS["x4b_datacenter"])),
              ("cloudflare_datacenter",24,lambda: cloudflare.refresh(conn)),
              ("device_browser_proxy",6,lambda: device_browser_info.refresh(conn))]
            rir_urls = {
                "APNIC": os.getenv("RIR_APNIC_URL", "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest"),
                "RIPE": os.getenv("RIR_RIPE_URL", "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest"),
                "ARIN": os.getenv("RIR_ARIN_URL", "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest"),
                "LACNIC": os.getenv("RIR_LACNIC_URL", "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest"),
                "AFRINIC": os.getenv("RIR_AFRINIC_URL", "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest"),
            }
            if os.getenv("GEO_RIR_REFRESH_ENABLED", "true").lower() in {"1", "true", "yes", "on"}:
                for rir, url in rir_urls.items():
                    jobs.append((f"rir:{rir.lower()}", 24, lambda rir=rir, url=url: global_geo.refresh_rir(conn, rir, url)))
            geofeeds = [item.strip().split("=", 1) for item in os.getenv("GEOFEED_SOURCES", "").split(",") if "=" in item]
            for name, url in geofeeds:
                jobs.append((f"geofeed:{name}", 168, lambda name=name, url=url: global_geo.refresh_geofeed(conn, name, url)))
            selected=os.getenv("FIREHOL_LISTS", ",".join(firehol.DEFAULT_LISTS)).split(",")
            for name in selected:
                name=name.strip()
                if name: jobs.append((f"firehol:{name}", 24, lambda name=name: firehol.refresh_list(conn,name)))
            for name,hours,task in jobs:
                if not _due(rows.get(name),now,hours): report[name]={"status":"not_due"}; continue
                try: result=task()
                except Exception as exc: result={"status":"failed","error":f"{type(exc).__name__}: {exc}"}
                _status(conn,name,now,result); report[name]=result; conn.commit()
            if os.getenv("DNSBL_ENABLED","false").lower() in {"1","true","yes","on"} and _due(rows.get("dnsbl_new_ips"),now,1):
                zones=[x.strip() for x in os.getenv("DNSBL_ZONES_INTERNAL","").split(",") if x.strip()]
                items=conn.execute("""SELECT o.ip FROM ip_observations o
                  WHERE o.behavior_score >= ? AND NOT EXISTS
                  (SELECT 1 FROM threat_indicators t WHERE t.network=o.ip AND t.source='dnsbl')""",
                  (int(os.getenv("DNSBL_SUSPICION_THRESHOLD","25")),)).fetchall()
                dns_report={"status":"updated","records_upserted":0}
                for item in items:
                    result=dnsbl.query_ip(conn,item["ip"],zones); dns_report["records_upserted"] += int(result.get("score",0)>0)
                _status(conn,"dnsbl_new_ips",now,dns_report); report["dnsbl_new_ips"]=dns_report
            conn.commit(); return {"status":"completed","sources":report}
        finally: conn.close()

def _x4b(conn, source, kind, url):
    if not url: return {"status":"not_configured","records_upserted":0}
    return cidr_lists.refresh_cidr_source(conn,source,url,kind)

if __name__ == "__main__":
    print(json.dumps(run_due_sources(), indent=2, default=str))
