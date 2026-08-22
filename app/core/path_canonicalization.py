"""Canonical URL paths for statistical detection evidence."""

from __future__ import annotations

import re


_UUID_SEGMENT = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_HASH_SEGMENT = re.compile(r"^[0-9a-f]{16,64}$", re.IGNORECASE)
_NUMERIC_SEGMENT = re.compile(r"^[0-9]+$")


def canonicalize_path(path: str | None) -> str:
    """Return stable path shape without changing case or raw event data.

    Query strings are removed. Repeated slashes collapse. Complete dynamic
    path segments become ``{uuid}``, ``{hash}``, or ``{id}``.
    """

    if not path:
        return ""
    pathname = str(path).split("?", 1)[0].split("#", 1)[0]
    if not pathname:
        return "/" if str(path).startswith("/") else ""
    leading = pathname.startswith("/")
    trailing = pathname.endswith("/") and pathname != "/"
    segments = [segment for segment in pathname.split("/") if segment]
    normalized: list[str] = []
    for segment in segments:
        if _UUID_SEGMENT.fullmatch(segment):
            normalized.append("{uuid}")
        elif _NUMERIC_SEGMENT.fullmatch(segment):
            normalized.append("{id}")
        elif _HASH_SEGMENT.fullmatch(segment):
            normalized.append("{hash}")
        else:
            normalized.append(segment)
    result = "/".join(normalized)
    if leading:
        result = "/" + result
    if trailing and result != "/":
        result += "/"
    return result or ("/" if leading else "")
