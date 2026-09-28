"""Collector runtime configuration."""

from __future__ import annotations

from dataclasses import dataclass
import os


def _env_int(name: str, default: int, minimum: int) -> int:
    """Read an integer environment setting and enforce its minimum value."""
    try:
        return max(minimum, int(os.getenv(name, str(default))))
    except (TypeError, ValueError):
        return default


@dataclass(frozen=True)
class CollectorConfig:
    enabled: bool
    url: str
    token: str
    log_key: str
    source_id: str
    batch_size: int
    flush_ms: int
    ai_interval_seconds: int = 300

    @classmethod
    def from_env(cls) -> "CollectorConfig":
        """Build collector settings from the process environment."""
        enabled = os.getenv("LOG_WS_ENABLED", "false").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        return cls(
            enabled=enabled,
            url=os.getenv("LOG_WS_URL", "").strip(),
            token=os.getenv("LOG_WS_TOKEN", "").strip(),
            log_key=os.getenv("LOG_WS_LOG_KEY", "access").strip() or "access",
            source_id=os.getenv("LOG_WS_SOURCE_ID", "azure-access").strip()
            or "azure-access",
            batch_size=_env_int("LOG_WS_BATCH_SIZE", 200, 1),
            flush_ms=_env_int("LOG_WS_FLUSH_MS", 1000, 50),
            ai_interval_seconds=_env_int("AI_RUNTIME_INTERVAL_SECONDS", 300, 1),
        )

    @property
    def valid(self) -> bool:
        """Report whether required connection and source settings are present."""
        return bool(self.url and self.token and self.log_key and self.source_id)
