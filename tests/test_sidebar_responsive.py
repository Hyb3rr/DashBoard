from pathlib import Path


SIDEBAR_JS = Path("app/web/static/sidebar.js").read_text()
DASHBOARD_CSS = Path("app/web/static/dashboard.css").read_text()


def test_desktop_sidebar_remains_sticky_and_not_relative():
    assert ".shell > aside { position: sticky; top: 0; height: 100vh; }" in SIDEBAR_JS
    assert "aside { position: relative; }" not in SIDEBAR_JS
    assert "position:sticky" in DASHBOARD_CSS


def test_collapsed_desktop_sidebar_keeps_icon_navigation_visible():
    assert ".shell.sidebar-collapsed > aside nav { display: none; }" not in SIDEBAR_JS
    assert ".shell.sidebar-collapsed > aside nav a { font-size: 0; }" in SIDEBAR_JS
    assert ".shell.sidebar-collapsed > aside nav a > span { font-size: 16px; }" in SIDEBAR_JS


def test_collapse_state_remains_persistent():
    assert "localStorage.getItem(STORAGE_KEY)" in SIDEBAR_JS
    assert "localStorage.setItem(STORAGE_KEY" in SIDEBAR_JS
    assert "shell.classList.toggle('sidebar-collapsed', collapsed)" in SIDEBAR_JS
