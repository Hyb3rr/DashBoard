"""Deterministic, batch-only page classification for demand evidence."""

from __future__ import annotations

from fnmatch import fnmatchcase
from typing import Any, Iterable
from urllib.parse import urlsplit


VALID_TYPES = {"product", "content", "other"}


def classify_page(path: str | None, rules: Iterable[dict[str, Any]]) -> str:
    """Match the highest-priority path rule, defaulting unmatched paths to other."""
    candidate = urlsplit(str(path or "")).path or "/"
    ordered = sorted(
        (rule for rule in rules if rule.get("active", True) and rule.get("page_type") in VALID_TYPES and rule.get("pattern")),
        key=lambda rule: (-int(rule.get("priority", 0)), int(rule.get("id", 0) or 0)),
    )
    for rule in ordered:
        pattern = str(rule["pattern"])
        wildcard = pattern.replace("%", "*")
        if fnmatchcase(candidate, wildcard):
            return str(rule["page_type"])
    return "other"


def is_product_page(path: str | None, rules: Iterable[dict[str, Any]]) -> bool:
    """Return whether the page rules classify this path as a product page."""
    return classify_page(path, rules) == "product"


__all__ = ["classify_page", "is_product_page"]
