"""Shared high-confidence web security path markers."""

from __future__ import annotations


SECURITY_MARKERS: tuple[tuple[str, str], ...] = (
    ("/.env", "sensitive_path_probe"),
    ("/.git", "sensitive_path_probe"),
    ("/wp-config.php", "sensitive_path_probe"),
    ("/xmlrpc.php", "sensitive_path_probe"),
    ("/vendor/phpunit", "sensitive_path_probe"),
    ("/phpmyadmin", "sensitive_path_probe"),
    ("/adminer", "sensitive_path_probe"),
)


def match_security_marker(path: str | None) -> tuple[str, str] | None:
    """Return (rule_id, marker) for a sensitive request path, if present."""
    normalized = (path or "").split("?", 1)[0].lower()
    for marker, rule_id in SECURITY_MARKERS:
        if marker in normalized:
            return rule_id, marker
    return None
