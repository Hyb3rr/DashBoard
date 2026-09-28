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

from app.config.settings import TOR_EXIT_LIST


DEFAULT_URL = "https://check.torproject.org/torbulkexitlist"
IP1_URL = "https://ip1.info/tor-ips/tor-ips.txt"
DEFAULT_OUTPUT = TOR_EXIT_LIST


def _valid_ips(payload: bytes) -> list[str]:
    """Parse and deduplicate globally routable IPv4 and IPv6 addresses."""
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


def _load_metadata(path: Path) -> dict:
    """Load prior feed metadata while treating unreadable cache as empty."""
    try:
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _source_urls(url: str | None) -> list[str]:
    """Select the explicit test override or the configured production feeds."""
    if url is not None:
        return [url]
    return [
        os.getenv("TOR_EXIT_LIST_URL", DEFAULT_URL),
        os.getenv("TOR_EXIT_LIST_IP1_URL", IP1_URL),
    ]


def _fetch_source(source_url: str, timeout: float) -> dict:
    """Fetch one feed and return validated IPs or a structured failure."""
    request = Request(source_url, headers={"User-Agent": "SentinelHub-TorList/1.0"})
    try:
        with urlopen(request, timeout=timeout) as response:
            source_ips = _valid_ips(response.read())
            if not source_ips:
                return {"status": "failed", "error": "empty_or_invalid_list"}
            return {
                "status": "updated",
                "ips": source_ips,
                "report": {
                    "count": len(source_ips),
                    "etag": response.headers.get("ETag"),
                    "last_modified": response.headers.get("Last-Modified"),
                },
            }
    except HTTPError as exc:
        if exc.code == 304:
            return {"status": "not_modified"}
        return {"status": "failed", "error": f"HTTP {exc.code}"}
    except (TimeoutError, URLError, OSError) as exc:
        return {"status": "failed", "error": type(exc).__name__}


def _write_not_modified_metadata(path: Path, metadata: dict) -> dict:
    """Record a successful conditional check without replacing the feed file."""
    metadata["last_checked_at"] = datetime.now(timezone.utc).isoformat()
    metadata["status"] = "not_modified"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    return {"status": "not_modified", "count": metadata.get("count", 0)}


def _write_ips_atomically(output: Path, ips: list[str]) -> None:
    """Replace the current feed only after the complete temporary file is durable."""
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


def refresh_tor_exit_list(
    output_path: str | Path = DEFAULT_OUTPUT,
    metadata_path: str | Path | None = None,
    url: str | None = None,
    timeout: float = 20.0,
) -> dict:
    """Refresh the Tor exit-node list from configured feeds or one explicit URL."""
    output = Path(output_path)
    metadata = Path(metadata_path) if metadata_path else output.with_suffix(output.suffix + ".meta.json")
    old_meta = _load_metadata(metadata)
    single_source = url is not None
    source_urls = _source_urls(url)
    merged: set[str] = set()
    source_reports = {}
    for source_url in source_urls:
        fetched = _fetch_source(source_url, timeout)
        if fetched["status"] == "not_modified" and single_source:
            result = _write_not_modified_metadata(metadata, old_meta)
            return {**result, "path": str(output)}
        if fetched["status"] != "updated":
            return {
                "status": "failed", "error": fetched["error"],
                "source": source_url, "path": str(output),
            }
        source_reports[source_url] = fetched["report"]
        merged.update(fetched["ips"])

    ips = sorted(merged, key=lambda value: (ipaddress.ip_address(value).version, ipaddress.ip_address(value)))
    old_count = int(old_meta.get("count") or 0)
    if old_count and len(ips) < old_count * 0.5:
        return {"status": "failed", "error": "sanity_count_drop", "path": str(output), "count": len(ips)}

    _write_ips_atomically(output, ips)

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
    """Parse command-line options and report the feed refresh result."""
    parser = argparse.ArgumentParser(description="Refresh the local Tor exit-node list")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--url", default=None, help="Use one source only (default: Tor Project + IP1)")
    args = parser.parse_args()
    result = refresh_tor_exit_list(output_path=args.output, url=args.url)
    print(json.dumps(result))
    return 0 if result["status"] in {"updated", "not_modified"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
