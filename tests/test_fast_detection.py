from app.core.fast_detection import detect_raw_line


def _line(request: str, user_agent: str = "normal-client") -> str:
    return (
        '203.0.113.10 - - [24/Aug/2026:12:00:00 +0000] '
        f'"{request}" 404 123 "-" "{user_agent}"'
    )


def test_sensitive_path_is_detected_from_raw_request_line():
    result = detect_raw_line(_line("GET /.env?from=probe HTTP/1.1"))

    assert result is not None
    assert result.rule_id == "sensitive_path_probe"
    assert result.marker == "/.env"
    assert result.path == "/.env?from=probe"


def test_normal_request_and_post_alone_do_not_alert():
    assert detect_raw_line(_line("GET /index.html HTTP/1.1")) is None
    assert detect_raw_line(_line("POST /login HTTP/1.1")) is None


def test_marker_in_user_agent_does_not_alert():
    assert detect_raw_line(
        _line("GET /index.html HTTP/1.1", "scanner /.env /.git/")
    ) is None


def test_malformed_raw_line_does_not_alert():
    assert detect_raw_line("not an apache access log line /.env") is None
