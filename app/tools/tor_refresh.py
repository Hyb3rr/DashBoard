"""Safely refresh the local Tor exit-node list from public bulk exports."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import tempfile
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from ..config.settings import TOR_EXIT_LIST


DEFAULT_URL = "https://check.torproject.org/torbulkexitlist"
IP1_URL = "https://ip1.info/tor-ips/tor-ips.txt"
DEFAULT_OUTPUT = TOR_EXIT_LIST


def _valid_ips(payload: bytes) -> list[str]:
    values: set[str] = set()
    for raw in payload.decode("utf-8", errors="replace").splitlines():
        value = raw.strip()
        if not value or value.startswith("#"):
            continue
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        if address.is_global:
            values.add(str(address))
    return sorted(values, key=lambda value: (ipaddress.ip_address(value).version, ipaddress.ip_address(value)))


def refresh_tor_exit_list(
    output_path: str | Path = DEFAULT_OUTPUT,
    metadata_path: str | Path | None = None,
    url: str | None = None,
    timeout: float = 20.0,
) -> dict:
    """Refresh *output_path* using Tor Project + IP1, then atomically replace it.

    Passing ``url`` keeps the single-source mode used by tests and manual
    overrides. The scheduled/default mode fetches both sources and merges
    unique IPv4/IPv6 addresses. Existing data remains intact if a source
    fails, returns invalid data, or the merged list drops unexpectedly.
    """
    output = Path(output_path)
    metadata = Path(metadata_path) if metadata_path else output.with_suffix(output.suffix + ".meta.json")
    old_meta = {}
    if metadata.exists():
        try:
            old_meta = json.loads(metadata.read_text())
        except (OSError, json.JSONDecodeError):
            pass

    single_source = url is not None
    if single_source:
        source_urls = [url]
    else:
        source_urls = [
            os.getenv("TOR_EXIT_LIST_URL", DEFAULT_URL),
            os.getenv("TOR_EXIT_LIST_IP1_URL", IP1_URL),
        ]

    merged: set[str] = set()
    source_reports = {}
    for source_url in source_urls:
        request = Request(source_url, headers={"User-Agent": "SentinelHub-TorList/1.0"})
        try:
            with urlopen(request, timeout=timeout) as response:
                source_ips = _valid_ips(response.read())
                source_reports[source_url] = {
                    "count": len(source_ips),
                    "etag": response.headers.get("ETag"),
                    "last_modified": response.headers.get("Last-Modified"),
                }
        except HTTPError as exc:
            if exc.code == 304 and single_source:
                now = datetime.now(timezone.utc).isoformat()
                old_meta["last_checked_at"] = now
                old_meta["status"] = "not_modified"
                metadata.parent.mkdir(parents=True, exist_ok=True)
                metadata.write_text(json.dumps(old_meta, indent=2) + "\n", encoding="utf-8")
                return {"status": "not_modified", "path": str(output), "count": old_meta.get("count", 0)}
            return {"status": "failed", "error": f"HTTP {exc.code}", "source": source_url, "path": str(output)}
        except (TimeoutError, URLError, OSError) as exc:
            return {"status": "failed", "error": type(exc).__name__, "source": source_url, "path": str(output)}
        if not source_ips:
            return {"status": "failed", "error": "empty_or_invalid_list", "source": source_url, "path": str(output)}
        merged.update(source_ips)

    ips = sorted(merged, key=lambda value: (ipaddress.ip_address(value).version, ipaddress.ip_address(value)))
    old_count = int(old_meta.get("count") or 0)
    if old_count and len(ips) < old_count * 0.5:
        return {"status": "failed", "error": "sanity_count_drop", "path": str(output), "count": len(ips)}

    output.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as temp_file:
            temp_file.write("\n".join(ips) + "\n")
            temp_file.flush()
            os.fsync(temp_file.fileno())
        os.replace(temp_name, output)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass

    now = datetime.now(timezone.utc).isoformat()
    new_meta = {
        "url": source_urls[0] if single_source else None,
        "urls": source_urls,
        "sources": source_reports,
        "count": len(ips),
        "last_checked_at": now,
        "last_updated_at": now,
        "status": "updated",
    }
    if single_source:
        new_meta["etag"] = source_reports[source_urls[0]]["etag"]
        new_meta["last_modified"] = source_reports[source_urls[0]]["last_modified"]
    metadata.parent.mkdir(parents=True, exist_ok=True)
    metadata.write_text(json.dumps(new_meta, indent=2) + "\n", encoding="utf-8")
    return {"status": "updated", "count": len(ips), "path": str(output)}


def main() -> int:
    parser = argparse.ArgumentParser(description="Refresh the local Tor exit-node list")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--url", default=None, help="Use one source only (default: Tor Project + IP1)")
    args = parser.parse_args()
    result = refresh_tor_exit_list(output_path=args.output, url=args.url)
    print(json.dumps(result))
    return 0 if result["status"] in {"updated", "not_modified"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
