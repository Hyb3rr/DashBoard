"""Device Browser CSV parsing shared by PostgreSQL persistence boundary."""
from __future__ import annotations

import io
import zipfile
from pathlib import Path


def _csv_payload(payload: bytes, source: str) -> bytes:
    """Extract provider CSV while rejecting unsafe/empty archives."""
    is_zip = payload[:4] == b"PK\x03\x04" or source.lower().split("?", 1)[0].endswith(".zip")
    if not is_zip:
        return payload
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        members = [item for item in archive.infolist() if not item.is_dir() and item.filename.lower().endswith(".csv")]
        safe = [item for item in members if not Path(item.filename).is_absolute() and ".." not in Path(item.filename).parts]
        if not safe:
            raise ValueError("Device Browser archive contains no safe CSV file")
        extracted = archive.read(max(safe, key=lambda item: item.file_size))
    if not extracted.strip():
        raise ValueError("Device Browser CSV payload is empty")
    return extracted


def refresh(conn, url: str | None = None, api_key: str | None = None, cache: Path | None = None) -> dict:
    from .pg_intel import refresh_device_browser

    return refresh_device_browser(conn, url=url, api_key=api_key, cache=cache)
