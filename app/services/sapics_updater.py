"""Download SAPICS GitHub Release MMDB assets safely."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

from .sapics_reader import ROOT, FILES

BASE = "https://github.com/sapics/ip-location-db/releases/download/latest/"
CHECKSUM = "https://github.com/sapics/ip-location-db/releases/download/checksum/"


def _fetch(url):
    with urlopen(Request(url, headers={"User-Agent": "ip-intelligence/sapics-updater"}), timeout=60) as response:
        return response.read()


def _expected(name):
    text = _fetch(CHECKSUM + name + ".sha256").decode("ascii", "replace").strip()
    return text.split()[0].lower()


def refresh() -> dict:
    ROOT.mkdir(parents=True, exist_ok=True)
    updated, errors = [], []
    for key, (folder, filename, _kind) in FILES.items():
        try:
            payload = _fetch(BASE + filename)
            digest = hashlib.sha256(payload).hexdigest()
            if digest != _expected(filename):
                raise ValueError(f"SHA-256 mismatch: {filename}")
            target_dir = ROOT / folder
            target_dir.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(dir=target_dir, prefix=f".{filename}.", delete=False) as tmp:
                tmp.write(payload)
                temporary = Path(tmp.name)
            import geoip2.database
            reader = geoip2.database.Reader(str(temporary))
            reader.close()
            temporary.replace(target_dir / filename)
            updated.append(filename)
        except Exception as exc:
            errors.append(f"{filename}: {type(exc).__name__}: {exc}")
    metadata = {"updated_at": datetime.now(timezone.utc).isoformat(), "updated": updated, "errors": errors}
    (ROOT / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return {"status": "ok" if not errors else "partial" if updated else "failed", **metadata}
