"""Safely refresh the local Tor exit-node list.

The monitored server is never contacted. This only updates a local Hub data
file from Tor Project's public bulk export.
"""

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
    url: str = DEFAULT_URL,
    timeout: float = 20.0,
) -> dict:
    """Refresh *output_path* using conditional HTTP and atomic replacement.

    Existing data remains intact for network errors, non-200 responses, or an
    invalid/empty response. Metadata is only updated after a validated list is
    committed.
    """
    output = Path(output_path)
    metadata = Path(metadata_path) if metadata_path else output.with_suffix(output.suffix + ".meta.json")
    headers = {"User-Agent": "SentinelHub-TorList/1.0"}
    old_meta = {}
    if metadata.exists():
        try:
            old_meta = json.loads(metadata.read_text())
            if old_meta.get("etag"):
                headers["If-None-Match"] = old_meta["etag"]
            if old_meta.get("last_modified"):
                headers["If-Modified-Since"] = old_meta["last_modified"]
        except (OSError, json.JSONDecodeError):
            pass

    request = Request(url, headers=headers)
    try:
        with urlopen(request, timeout=timeout) as response:
            payload = response.read()
            response_headers = response.headers
    except HTTPError as exc:
        if exc.code == 304:
            now = datetime.now(timezone.utc).isoformat()
            old_meta["last_checked_at"] = now
            old_meta["status"] = "not_modified"
            metadata.write_text(json.dumps(old_meta, indent=2) + "\n", encoding="utf-8")
            return {"status": "not_modified", "path": str(output), "count": old_meta.get("count", 0)}
        return {"status": "failed", "error": f"HTTP {exc.code}", "path": str(output)}
    except (TimeoutError, URLError, OSError) as exc:
        return {"status": "failed", "error": type(exc).__name__, "path": str(output)}

    ips = _valid_ips(payload)
    if not ips:
        return {"status": "failed", "error": "empty_or_invalid_list", "path": str(output)}
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

    new_meta = {
        "url": url,
        "etag": response_headers.get("ETag"),
        "last_modified": response_headers.get("Last-Modified"),
        "count": len(ips),
        "last_checked_at": datetime.now(timezone.utc).isoformat(),
        "last_updated_at": datetime.now(timezone.utc).isoformat(),
        "status": "updated",
    }
    metadata.write_text(json.dumps(new_meta, indent=2) + "\n", encoding="utf-8")
    return {"status": "updated", "count": len(ips), "path": str(output)}


def main() -> int:
    parser = argparse.ArgumentParser(description="Refresh the local Tor exit-node list")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--url", default=os.getenv("TOR_EXIT_LIST_URL", DEFAULT_URL))
    args = parser.parse_args()
    result = refresh_tor_exit_list(output_path=args.output, url=args.url)
    print(json.dumps(result))
    return 0 if result["status"] in {"updated", "not_modified"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
