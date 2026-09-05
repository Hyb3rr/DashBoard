"""Explicit failure hooks for replay/transaction tests.

The default hook is a no-op, so production does not depend on environment
variables or test-only branches. Tests can inject a hook into the collector
or repository and raise at a named point.
"""

from __future__ import annotations

from typing import Protocol


class Failpoint(Protocol):
    def hit(self, name: str) -> None: ...


class NoopFailpoint:
    def hit(self, name: str) -> None:
        return None


class CrashFailpoint:
    def __init__(self, target: str, *, error: type[BaseException] = RuntimeError) -> None:
        self.target = target
        self.error = error
        self.hits: list[str] = []

    def hit(self, name: str) -> None:
        self.hits.append(name)
        if name == self.target:
            raise self.error(f"failure injection: {name}")
