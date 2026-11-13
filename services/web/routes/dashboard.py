"""Dashboard routes for Apex Web Admin Portal."""

from __future__ import annotations

from fastapi import APIRouter, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from shared.config import settings
from services.web.data.seed_data import (
    COMPANY_NAME,
    PORTAL_TITLE,
    RECENT_ACTIVITIES,
    SYSTEM_NODES,
)
from services.web.security import get_session

router = APIRouter()
templates = Jinja2Templates(directory=str(settings.WEB_BASE_DIR / "templates"))


@router.get("/", response_class=HTMLResponse)
@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    """Render the executive operations dashboard."""
    session_id = request.cookies.get("apex_session")
    sess = get_session(session_id)
    if not sess:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "company_name": COMPANY_NAME,
            "portal_title": PORTAL_TITLE,
            "active_page": "dashboard",
            "username": sess["username"],
            "role": sess["role"],
            "activities": RECENT_ACTIVITIES,
            "nodes": SYSTEM_NODES,
        },
    )
