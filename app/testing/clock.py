"""Small injectable UTC clock used by deterministic pipeline tests."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Iterator


_fixed_now: ContextVar[datetime | None] = ContextVar("fixed_now", default=None)


def utcnow() -> datetime:
    value = _fixed_now.get()
    return value or datetime.now(timezone.utc)


@contextmanager
def freeze(value: datetime) -> Iterator[None]:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    token = _fixed_now.set(value.astimezone(timezone.utc))
    try:
        yield
    finally:
        _fixed_now.reset(token)
