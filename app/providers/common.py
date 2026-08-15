from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen


def atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def meta_path(path: Path) -> Path:
    return path.with_name(path.name + ".meta.json")


def read_meta(path: Path) -> dict:
    try:
        value = json.loads(meta_path(path).read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def conditional_fetch(url: str, cache: Path | None = None, headers: dict | None = None, timeout: int = 30) -> dict:
    request_headers = dict(headers or {})
    if cache and cache.exists():
        old = read_meta(cache)
        if old.get("etag"):
            request_headers["If-None-Match"] = old["etag"]
        if old.get("last_modified"):
            request_headers["If-Modified-Since"] = old["last_modified"]
    request = Request(url, headers=request_headers)
    try:
        with urlopen(request, timeout=timeout) as response:
            payload = response.read()
            response_headers = {str(k).lower().replace("-", "_"): v for k, v in response.headers.items()}
            if cache:
                atomic_write(cache, payload)
                atomic_write(meta_path(cache), json.dumps({
                    "etag": response_headers.get("etag"),
                    "last_modified": response_headers.get("last_modified"),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }).encode())
            return {"status": "updated", "payload": payload, "headers": response_headers}
    except HTTPError as exc:
        if exc.code == 304 and cache and cache.exists():
            return {"status": "not_modified", "payload": cache.read_bytes(), "headers": read_meta(cache)}
        raise


def parse_networks(payload: bytes | str) -> list[str]:
    text = payload.decode("utf-8", "replace") if isinstance(payload, bytes) else payload
    result = []
    import ipaddress
    for raw in text.splitlines():
        value = raw.split("#", 1)[0].split(";", 1)[0].strip().split()[0] if raw.strip() else ""
        if not value:
            continue
        try:
            if "/" not in value:
                value = f"{value}/32" if ":" not in value else f"{value}/128"
            result.append(str(ipaddress.ip_network(value, strict=False)))
        except (ValueError, IndexError):
            continue
    return list(dict.fromkeys(result))
