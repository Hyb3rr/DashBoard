import ipaddress

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse, Response

from ..config.settings import TEMPLATES_DIR

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def dashboard():
    """Serve the main monitoring dashboard shell."""
    return HTMLResponse((TEMPLATES_DIR / "dashboard.html").read_text())


@router.get("/favicon.ico")
def favicon():
    """Return an empty favicon response."""
    return Response(status_code=204)


@router.get("/ip/{ip}", response_class=HTMLResponse)
def ip_case_page(ip: str):
    """Validate an IP address and serve its investigation page."""
    try:
        ipaddress.ip_address(ip)
    except ValueError as exc:
        raise HTTPException(400, "Invalid IP address") from exc
    return HTMLResponse((TEMPLATES_DIR / "ip_detail.html").read_text())


@router.get("/regions", response_class=HTMLResponse)
def region_profiles_page():
    """Serve the region profile listing page."""
    return HTMLResponse((TEMPLATES_DIR / "regions.html").read_text())


@router.get("/map", response_class=HTMLResponse)
def map_page():
    """Serve the global intelligence map page."""
    return HTMLResponse((TEMPLATES_DIR / "map.html").read_text())


@router.get("/raw-logs", response_class=HTMLResponse)
def raw_logs_page():
    """Serve the raw log tail page."""
    return HTMLResponse((TEMPLATES_DIR / "raw_logs.html").read_text())


@router.get("/regions/{country_code}", response_class=HTMLResponse)
def region_profile_page(country_code: str):
    """Serve the country-level region detail page."""
    return HTMLResponse((TEMPLATES_DIR / "region_detail.html").read_text())
