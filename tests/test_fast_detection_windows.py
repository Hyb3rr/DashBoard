from app.core.fast_detection import (
    ShortWindowDetector,
    classify_wordpress_family,
    detect_scanner_user_agent,
    fanout_parts,
)


def _line(path: str, ip: str = "203.0.113.10", status: int = 404, user_agent: str = "client") -> str:
    return (
        f'{ip} - - [24/Aug/2026:12:00:00 +0000] "GET {path} HTTP/1.1" '
        f'{status} 1 "-" "{user_agent}"'
    )


def test_burst_crossing_threshold_emits_once_during_cooldown():
    detector = ShortWindowDetector(ttl_seconds=60, cooldown_seconds=60)
    alerts = []
    for index in range(100):
        alerts.extend(detector.observe(_line(f"/path-{index}"), now=float(index) / 10))

    assert [item.rule_id for item in alerts].count("WEB-BURST-001") == 1


def test_burst_below_threshold_does_not_alert():
    detector = ShortWindowDetector()

    for index in range(99):
        assert detector.observe(_line("/same-path"), now=float(index) / 10) == []


def test_ttl_expires_window_state():
    detector = ShortWindowDetector(ttl_seconds=10)
    detector.observe(_line("/one"), now=0)

    assert detector.active_ip_count(now=9) == 1
    assert detector.active_ip_count(now=10) == 0


def test_login_burst_and_path_scan_use_separate_rules():
    detector = ShortWindowDetector(ttl_seconds=60, cooldown_seconds=60)
    login_alerts = []
    for index in range(21):
        login_alerts.extend(detector.observe(_line("/wp-login.php"), now=float(index)))
    scan_alerts = []
    for index in range(81):
        scan_alerts.extend(detector.observe(_line(f"/scan-{index}"), now=30 + float(index) / 10))

    assert any(item.rule_id == "WEB-BRUTE-001" for item in login_alerts)
    assert any(item.rule_id == "WEB-SCAN-001" for item in scan_alerts)


def test_content_discovery_sweep_uses_path_shape_and_4xx_ratio():
    detector = ShortWindowDetector(ttl_seconds=60, cooldown_seconds=60)
    alerts = []
    for index in range(20):
        alerts.extend(detector.observe(_line(f"/candidate-{index}"), now=float(index)))

    matches = [item for item in alerts if item.rule_id == "PENTEST-DISC-001"]
    assert len(matches) == 1
    assert matches[0].shadow_only is True


def test_content_discovery_sweep_rejects_low_novelty_or_low_4xx():
    detector = ShortWindowDetector(ttl_seconds=60)
    for index in range(20):
        status = 200 if index < 10 else 404
        assert detector.observe(_line("/same", status=status), now=float(index)) == []


def test_canonical_paths_do_not_count_query_or_dynamic_ids_as_new_paths():
    detector = ShortWindowDetector(ttl_seconds=60)
    for index in range(20):
        assert detector.observe(_line(f"/item/{index}?probe={index}"), now=float(index)) == []


def test_wordpress_enumeration_counts_families_not_requests():
    detector = ShortWindowDetector(ttl_seconds=120, cooldown_seconds=120)
    paths = ["/wp-login.php", "/xmlrpc.php", "/wp-json/wp/v2/types"]
    alerts = []
    for index, path in enumerate(paths):
        alerts.extend(detector.observe(_line(path), now=float(index)))
    matches = [item for item in alerts if item.rule_id == "PENTEST-WP-001"]
    assert len(matches) == 1


def test_wordpress_static_assets_do_not_create_discovery_family():
    assert classify_wordpress_family("/wp-content/themes/site/main.css") is None
    assert classify_wordpress_family("/wp-content/plugins/site/app.js") is None


def test_extension_backup_fanout_groups_variants_by_base_path():
    detector = ShortWindowDetector(ttl_seconds=60, cooldown_seconds=60)
    alerts = []
    for index, path in enumerate(("/config", "/config.php", "/config.bak", "/config.old")):
        alerts.extend(detector.observe(_line(path), now=float(index)))
    assert sum(item.rule_id == "PENTEST-FANOUT-001" for item in alerts) == 1
    assert fanout_parts("/logo.png") == ("/logo.png", "")


def test_scanner_user_agent_is_shadow_only_supporting_signal():
    detector = ShortWindowDetector(cooldown_seconds=60)
    alerts = detector.observe(_line("/index", user_agent="Fuzz Faster U Fool v2.1"), now=0)
    assert detect_scanner_user_agent(_line("/index", user_agent="sqlmap/1.8")) == "sqlmap"
    assert [(item.rule_id, item.shadow_only) for item in alerts] == [("PENTEST-UA-001", True)]


def test_detector_state_expires_and_respects_ip_capacity():
    detector = ShortWindowDetector(ttl_seconds=10, max_ips=2)
    detector.observe(_line("/one", ip="203.0.113.1"), now=0)
    assert detector.active_ip_count(now=9) == 1
    detector.observe(_line("/two", ip="203.0.113.2"), now=9)
    detector.observe(_line("/three", ip="203.0.113.3"), now=9)
    assert detector.active_ip_count(now=9) == 2
    assert detector.active_ip_count(now=10) == 2
