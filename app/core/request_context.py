"""Safe request-correlation helpers for HTTP observability."""

from __future__ import annotations

import re
import uuid


_REQUEST_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def request_id(value: str | None) -> str:
    """Keep a safe caller request ID or generate a new correlation ID."""
    candidate = str(value or "").strip()
    if _REQUEST_ID.fullmatch(candidate):
        return candidate
    return uuid.uuid4().hex
