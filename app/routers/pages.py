import ipaddress

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse, Response

from ..config.settings import APP_DIR

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def dashboard():
    return HTMLResponse((APP_DIR / "dashboard.html").read_text())


@router.get("/favicon.ico")
def favicon():
    return Response(status_code=204)


@router.get("/ip/{ip}", response_class=HTMLResponse)
def ip_case_page(ip: str):
    try:
        ipaddress.ip_address(ip)
    except ValueError as exc:
        raise HTTPException(400, "Invalid IP address") from exc
    return HTMLResponse((APP_DIR / "ip_detail.html").read_text())


@router.get("/regions", response_class=HTMLResponse)
def region_profiles_page():
    return HTMLResponse((APP_DIR / "regions.html").read_text())


@router.get("/regions/{country_code}", response_class=HTMLResponse)
def region_profile_page(country_code: str):
    return HTMLResponse((APP_DIR / "region_detail.html").read_text())
