"""Pure, low-latency detection for raw Apache access-log lines."""

from __future__ import annotations

from dataclasses import dataclass
from collections import deque
from datetime import datetime, timezone
import re
from collections import Counter, defaultdict

from .path_canonicalization import canonicalize_path
from .security_markers import match_security_marker


_REQUEST_LINE = re.compile(r'"(?P<method>[A-Z]+) (?P<path>\S+) [^"]+"')
_ACCESS_LINE = re.compile(
    r'^(?P<ip>\S+) .*?"(?P<method>[A-Z]+) (?P<path>\S+) [^"]+" (?P<status>\d{3}) '
)
_SCANNER_USER_AGENTS = (
    ("Fuzz Faster U Fool", "ffuf"),
    ("feroxbuster", "feroxbuster"),
    ("gobuster", "gobuster"),
    ("dirsearch", "dirsearch"),
    ("sqlmap", "sqlmap"),
    ("nikto", "nikto"),
    ("commix", "commix"),
)
_FANOUT_SUFFIXES = (".bak2", ".orig", ".save", ".bak", ".old", ".php", ".1", "~")


@dataclass(frozen=True)
class EarlyDetection:
    rule_id: str
    marker: str
    method: str
    path: str
    ip: str | None = None
    shadow_only: bool = False
    scanner_tool: str | None = None


@dataclass(frozen=True)
class _WindowEntry:
    timestamp: float
    path: str
    canonical_path: str
    method: str
    status: int
    is_wp_login: bool
    is_4xx: bool
    scanner_tool: str | None = None
    wp_family: str | None = None
    fanout_base: str | None = None
    fanout_variant: str | None = None


class ShortWindowDetector:
    """Bounded per-IP correlation state for preliminary alerts."""

    def __init__(self, ttl_seconds: int = 60, cooldown_seconds: int = 60, max_ips: int = 10000) -> None:
        self.ttl_seconds = max(1, ttl_seconds)
        self.cooldown_seconds = max(0, cooldown_seconds)
        self.max_ips = max(1, max_ips)
        self._windows: dict[str, deque[_WindowEntry]] = {}
        self._last_alert: dict[tuple[str, str], float] = {}
        self._path_counts: dict[str, Counter[str]] = defaultdict(Counter)
        self._wp_families: dict[str, Counter[str]] = defaultdict(Counter)
        self._fanout_variants: dict[str, dict[str, Counter[str]]] = defaultdict(lambda: defaultdict(Counter))

    def observe(self, raw_line: str | None, now: float | None = None) -> list[EarlyDetection]:
        parsed = _ACCESS_LINE.search(raw_line or "")
        if not parsed:
            return []
        stamp = now if now is not None else datetime.now(timezone.utc).timestamp()
        ip = parsed.group("ip")
        path = parsed.group("path")
        method = parsed.group("method")
        status = int(parsed.group("status"))
        canonical_path = canonicalize_path(path)
        scanner_tool = detect_scanner_user_agent(raw_line)
        wp_family = classify_wordpress_family(canonical_path)
        fanout_base, fanout_variant = fanout_parts(canonical_path)
        self._expire_ip(ip, stamp)
        entries = self._windows.setdefault(ip, deque())
        entry = _WindowEntry(
            stamp, path, canonical_path, method, status, "/wp-login.php" in path.lower(), status // 100 == 4,
            scanner_tool, wp_family, fanout_base, fanout_variant,
        )
        entries.append(entry)
        self._path_counts[ip][canonical_path] += 1
        if wp_family:
            self._wp_families[ip][wp_family] += 1
        if fanout_base is not None and fanout_variant is not None:
            self._fanout_variants[ip][fanout_base][fanout_variant] += 1
        self._enforce_capacity()
        current = list(entries)
        candidates: list[tuple[str, str]] = []
        if scanner_tool:
            candidates.append(("PENTEST-UA-001", "scanner_ua"))
        sensitive = detect_raw_line(raw_line)
        if sensitive:
            candidates.append((sensitive.rule_id, sensitive.marker))
        if sum(item.is_wp_login for item in current) > 20:
            candidates.append(("WEB-BRUTE-001", "wp_login_burst"))
        if len(current) >= 100:
            candidates.append(("WEB-BURST-001", "request_burst"))
        if len({item.path for item in current}) > 80:
            candidates.append(("WEB-SCAN-001", "path_scan"))
        unique_paths = len(self._path_counts[ip])
        if (
            len(current) >= 20
            and unique_paths >= 15
            and unique_paths / len(current) >= 0.70
            and sum(item.is_4xx for item in current) / len(current) >= 0.60
        ):
            candidates.append(("PENTEST-DISC-001", "content_discovery_sweep"))
        if len(self._wp_families[ip]) >= 3:
            candidates.append(("PENTEST-WP-001", "wordpress_enumeration_sequence"))
        if any(len(variants) >= 3 for variants in self._fanout_variants[ip].values()):
            candidates.append(("PENTEST-FANOUT-001", "extension_backup_fanout"))
        result = []
        for rule_id, marker in candidates:
            key = (ip, rule_id)
            if stamp - self._last_alert.get(key, float("-inf")) < self.cooldown_seconds:
                continue
            self._last_alert[key] = stamp
            is_shadow = rule_id.startswith("PENTEST-")
            result.append(EarlyDetection(rule_id, marker, method, path, ip, is_shadow, scanner_tool))
        return result

    def _expire_ip(self, ip: str, now: float) -> None:
        cutoff = now - self.ttl_seconds
        window = self._windows.get(ip)
        if window is not None:
            while window and window[0].timestamp <= cutoff:
                expired = window.popleft()
                self._path_counts[ip][expired.canonical_path] -= 1
                if not self._path_counts[ip][expired.canonical_path]:
                    del self._path_counts[ip][expired.canonical_path]
                if expired.wp_family:
                    self._wp_families[ip][expired.wp_family] -= 1
                    if not self._wp_families[ip][expired.wp_family]:
                        del self._wp_families[ip][expired.wp_family]
                if expired.fanout_base and expired.fanout_variant:
                    variants = self._fanout_variants[ip][expired.fanout_base]
                    variants[expired.fanout_variant] -= 1
                    if not variants[expired.fanout_variant]:
                        del variants[expired.fanout_variant]
                    if not variants:
                        del self._fanout_variants[ip][expired.fanout_base]
            if not window:
                self._windows.pop(ip, None)
                self._path_counts.pop(ip, None)
                self._wp_families.pop(ip, None)
                self._fanout_variants.pop(ip, None)

    def _expire(self, now: float) -> None:
        """Lazily clean all state only for explicit state-inspection calls."""
        for ip in tuple(self._windows):
            self._expire_ip(ip, now)
        for key, stamp in tuple(self._last_alert.items()):
            if now - stamp >= self.cooldown_seconds:
                del self._last_alert[key]

    def active_ip_count(self, now: float | None = None) -> int:
        self._expire(now if now is not None else datetime.now(timezone.utc).timestamp())
        return len(self._windows)

    def _enforce_capacity(self) -> None:
        while len(self._windows) > self.max_ips:
            oldest_ip = min(self._windows, key=lambda ip: self._windows[ip][-1].timestamp)
            del self._windows[oldest_ip]
            self._path_counts.pop(oldest_ip, None)
            self._wp_families.pop(oldest_ip, None)
            self._fanout_variants.pop(oldest_ip, None)


def detect_scanner_user_agent(raw_line: str | None) -> str | None:
    if not raw_line:
        return None
    quoted = re.findall(r'"([^"]*)"', raw_line)
    user_agent = quoted[-1].lower() if quoted else ""
    for needle, tool in _SCANNER_USER_AGENTS:
        if needle.lower() in user_agent:
            return tool
    return None


def classify_wordpress_family(path: str | None) -> str | None:
    value = (path or "").lower().rstrip("/") or "/"
    if value == "/wp-login.php":
        return "wp_login"
    if value == "/xmlrpc.php":
        return "wp_xmlrpc"
    if value == "/wp-json" or value.startswith("/wp-json/"):
        return "wp_rest"
    if value == "/readme.html":
        return "wp_core_metadata"
    if re.fullmatch(r"/wp-content/plugins/[^/]+/readme\.txt", value):
        return "wp_plugin_metadata"
    if re.fullmatch(r"/wp-content/themes/[^/]+/(?:readme\.txt|style\.css)", value):
        return "wp_theme_metadata"
    if value.startswith("/wp-content/uploads/"):
        return "wp_uploads_probe"
    if value == "/wp-admin" or value.startswith("/wp-admin/"):
        return "wp_admin"
    return None


def fanout_parts(path: str | None) -> tuple[str | None, str | None]:
    value = path or ""
    for suffix in _FANOUT_SUFFIXES:
        if value.endswith(suffix) and len(value) > len(suffix) and value.rsplit("/", 1)[-1] != suffix[1:]:
            return value[:-len(suffix)] or "/", suffix
    return value or None, ""


def detect_raw_line(raw_line: str | None) -> EarlyDetection | None:
    """Detect high-confidence path probes without DB, network, or async work."""
    if not raw_line:
        return None
    request = _REQUEST_LINE.search(raw_line)
    if not request:
        return None
    match = match_security_marker(request.group("path"))
    if not match:
        return None
    rule_id, marker = match
    return EarlyDetection(
        rule_id=rule_id,
        marker=marker,
        method=request.group("method"),
        path=request.group("path"),
        ip=raw_line.split(None, 1)[0] if raw_line.split(None, 1) else None,
    )
