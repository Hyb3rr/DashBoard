"""Parsers for global registration and owner-declared location snapshots."""
from __future__ import annotations

import csv
import io
import os
from datetime import datetime, timezone
from pathlib import Path

from .common import conditional_fetch


def _upsert_prefix(conn, network: str, source: str, **values) -> None:
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """INSERT INTO geo_prefixes
           (network,asn,organization,network_type,rir,registration_country,source,source_version,first_seen,last_seen,active,metadata_json)
           VALUES(?,?,?,?,?,?,?,?,?,?,1,?)
           ON CONFLICT(network,source) DO UPDATE SET asn=excluded.asn,organization=excluded.organization,
             network_type=excluded.network_type,rir=excluded.rir,registration_country=excluded.registration_country,
             source_version=excluded.source_version,last_seen=excluded.last_seen,active=1,metadata_json=excluded.metadata_json""",
        (network, values.get("asn"), values.get("organization"), values.get("network_type"), values.get("rir"),
         values.get("registration_country"), source, values.get("source_version"), now, now, values.get("metadata_json", "{}")),
    )


def _prefix_params(rows: list[dict], source: str, now: str, rir: str) -> list[tuple]:
    return [
        (
            row["network"], None, None, None, rir, row["country_code"],
            source, None, now, now, "{}",
        )
        for row in rows
    ]


def parse_rir_delegated(payload: str, rir: str) -> list[dict]:
    """Parse RIR delegated-extended records into normalized IPv4/IPv6 rows."""
    rows = []
    import ipaddress

    for raw in payload.splitlines():
        if not raw or raw.startswith("#"):
            continue
        fields = raw.split("|")
        if len(fields) < 7 or fields[2] not in {"ipv4", "ipv6"} or fields[6] not in {"allocated", "assigned"}:
            continue
        try:
            start, count = fields[3], int(fields[4])
            if fields[2] == "ipv4":
                first = ipaddress.ip_address(start)
                last = ipaddress.ip_address(int(first) + count - 1)
                networks = ipaddress.summarize_address_range(first, last)
            else:
                # RIR delegated files store the IPv6 prefix length in the
                # count column, unlike IPv4 where it is an address count.
                networks = [ipaddress.ip_network(f"{start}/{count}", strict=False)]
            rows.extend({"network": str(network), "country_code": fields[1].upper(), "rir": rir} for network in networks)
        except (ValueError, OverflowError):
            continue
    return rows


def refresh_rir(conn, rir: str, url: str, cache: Path | None = None) -> dict:
    cache = cache or Path(os.getenv(f"{rir.upper()}_DELEGATED_CACHE", f"data/geo/{rir.lower()}-delegated.txt"))
    try:
        result = conditional_fetch(url, cache)
        rows = parse_rir_delegated(result["payload"].decode("utf-8", "replace"), rir)
        if not rows:
            return {"status": "failed", "error": "empty or invalid RIR delegated payload", "records_upserted": 0}
        conn.execute("UPDATE geo_prefixes SET active=0 WHERE source=?", (f"rir:{rir.lower()}",))
        source = f"rir:{rir.lower()}"
        conn.executemany(
            """INSERT INTO geo_prefixes
               (network,asn,organization,network_type,rir,registration_country,source,source_version,first_seen,last_seen,active,metadata_json)
               VALUES(?,?,?,?,?,?,?,?,?,?,1,?)
               ON CONFLICT(network,source) DO UPDATE SET
                 rir=excluded.rir, registration_country=excluded.registration_country,
                 last_seen=excluded.last_seen, active=1, metadata_json=excluded.metadata_json""",
            _prefix_params(rows, source, datetime.now(timezone.utc).isoformat(), rir),
        )
        conn.commit()
        return {"status": result["status"], "records_upserted": len(rows), "source": f"rir:{rir.lower()}"}
    except Exception as exc:
        return {"status": "failed", "error": f"{type(exc).__name__}: {exc}", "records_upserted": 0}


def parse_geofeed(payload: str) -> list[dict]:
    rows = []
    for row in csv.reader(io.StringIO(payload)):
        if len(row) < 2 or row[0].strip().startswith("#"):
            continue
        network, country = row[0].strip(), row[1].strip().upper()
        if len(country) != 2:
            continue
        try:
            import pycountry

            if not pycountry.countries.get(alpha_2=country):
                continue
        except ImportError:
            pass
        try:
            import ipaddress

            network = str(ipaddress.ip_network(network, strict=False))
        except ValueError:
            continue
        rows.append({"network": network, "country_code": country})
    return rows


def refresh_geofeed(conn, name: str, url: str, cache: Path | None = None) -> dict:
    cache = cache or Path(os.getenv(f"GEOFEED_{name.upper()}_CACHE", f"data/geo/geofeed-{name}.csv"))
    try:
        result = conditional_fetch(url, cache)
        rows = parse_geofeed(result["payload"].decode("utf-8", "replace"))
        if not rows:
            return {"status": "failed", "error": "empty or invalid geofeed", "records_upserted": 0}
        now = datetime.now(timezone.utc).isoformat()
        source = f"geofeed:{name}"
        conn.executemany(
            """INSERT INTO geo_location_observations
               (network,country_code,country,source,source_confidence,location_scope,observed_at,metadata_json)
               VALUES(?,?,?,?,?,?,?,?)
               ON CONFLICT(network,source,location_scope) DO UPDATE SET country_code=excluded.country_code,
                 source_confidence=excluded.source_confidence,observed_at=excluded.observed_at""",
            [(row["network"], row["country_code"], None, source, 95, "network", now, "{}") for row in rows],
        )
        conn.commit()
        return {"status": result["status"], "records_upserted": len(rows), "source": source}
    except Exception as exc:
        return {"status": "failed", "error": f"{type(exc).__name__}: {exc}", "records_upserted": 0}
