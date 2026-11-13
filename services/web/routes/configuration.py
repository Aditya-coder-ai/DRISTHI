"""System configuration and bait credential trigger routes."""

from __future__ import annotations

from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from shared.config import settings
from services.web.data.seed_data import (
    COMPANY_NAME,
    PORTAL_TITLE,
    DECOY_CONFIGURATIONS,
)
from services.web.security import get_session, log_web_telemetry

router = APIRouter()
templates = Jinja2Templates(directory=str(settings.WEB_BASE_DIR / "templates"))


@router.get("/configuration", response_class=HTMLResponse)
async def configuration_page(request: Request):
    """Render system configuration profiles and decoy configuration files."""
    session_id = request.cookies.get("apex_session")
    sess = get_session(session_id)
    if not sess:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    src_ip = request.client.host if request.client else "127.0.0.1"
    src_port = request.client.port if request.client else 0
    user_agent = request.headers.get("user-agent", "Unknown")

    log_web_telemetry(
        {
            "eventid": "web.file.access",
            "src_ip": src_ip,
            "src_port": src_port,
            "username": sess["username"],
            "method": "GET",
            "path": "/configuration",
            "user_agent": user_agent,
            "session_id": session_id,
            "file_name": "system_configuration_profiles",
            "category": "infrastructure_config",
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    )

    return templates.TemplateResponse(
        request=request,
        name="configuration.html",
        context={
            "company_name": COMPANY_NAME,
            "portal_title": PORTAL_TITLE,
            "active_page": "configuration",
            "username": sess["username"],
            "role": sess["role"],
            "configs": DECOY_CONFIGURATIONS,
        },
    )


@router.get("/configuration/view/{config_name}")
async def view_configuration_file(config_name: str, request: Request):
    """Serve decoy configuration files containing planted bait credentials.
    
    Generates a HIGH-priority bait credential trigger event upon access.
    """
    session_id = request.cookies.get("apex_session")
    sess = get_session(session_id)
    if not sess:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    src_ip = request.client.host if request.client else "127.0.0.1"
    src_port = request.client.port if request.client else 0
    user_agent = request.headers.get("user-agent", "Unknown")

    if config_name in DECOY_CONFIGURATIONS:
        cfg = DECOY_CONFIGURATIONS[config_name]
        # Emit HIGH priority bait trigger event
        log_web_telemetry(
            {
                "eventid": "web.bait.trigger",
                "src_ip": src_ip,
                "src_port": src_port,
                "username": sess["username"],
                "method": "GET",
                "path": f"/configuration/view/{config_name}",
                "user_agent": user_agent,
                "session_id": session_id,
                "bait_file": config_name,
                "bait_credential_targeted": cfg.get("bait_user"),
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
        )
        return Response(
            content=cfg["raw"],
            media_type=cfg.get("content_type", "text/plain"),
        )

    # Suspicious config lookup
    log_web_telemetry(
        {
            "eventid": "web.suspicious.request",
            "src_ip": src_ip,
            "src_port": src_port,
            "username": sess["username"],
            "method": "GET",
            "path": f"/configuration/view/{config_name}",
            "user_agent": user_agent,
            "session_id": session_id,
            "reason": f"Attempted access to unlisted configuration file: {config_name}",
            "attack_vector": "Configuration Enumeration",
            "alert_priority": "MEDIUM",
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    )
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Configuration profile not found")
