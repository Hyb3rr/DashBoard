"""Explicit failure hooks for replay/transaction tests.

The default hook is a no-op, so production does not depend on environment
variables or test-only branches. Tests can inject a hook into the collector
or repository and raise at a named point.
"""

from __future__ import annotations

from typing import Protocol


class Failpoint(Protocol):
    def hit(self, name: str) -> None:
        """Invoke a named failure hook when the implementation supports it."""
        ...


class NoopFailpoint:
    def hit(self, name: str) -> None:
        """Ignore a failure hook when failure injection is disabled."""
        return None


class CrashFailpoint:
    def __init__(self, target: str, *, error: type[BaseException] = RuntimeError) -> None:
        """Configure a named hook that raises the selected exception type."""
        self.target = target
        self.error = error
        self.hits: list[str] = []

    def hit(self, name: str) -> None:
        """Record each hook call and raise when it matches the configured target."""
        self.hits.append(name)
        if name == self.target:
            raise self.error(f"failure injection: {name}")
