"""Employee directory routes for Apex Web Admin Portal."""

from __future__ import annotations

from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from shared.config import settings
from services.web.data.seed_data import COMPANY_NAME, PORTAL_TITLE, EMPLOYEES
from services.web.security import get_session, log_web_telemetry

router = APIRouter()
templates = Jinja2Templates(directory=str(settings.WEB_BASE_DIR / "templates"))


@router.get("/employees", response_class=HTMLResponse)
async def employees_page(request: Request):
    """Render the employee directory page."""
    session_id = request.cookies.get("apex_session")
    sess = get_session(session_id)
    if not sess:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    src_ip = request.client.host if request.client else "127.0.0.1"
    src_port = request.client.port if request.client else 0
    user_agent = request.headers.get("user-agent", "Unknown")

    # Record telemetry for directory access
    log_web_telemetry(
        {
            "eventid": "web.file.access",
            "src_ip": src_ip,
            "src_port": src_port,
            "username": sess["username"],
            "method": "GET",
            "path": "/employees",
            "user_agent": user_agent,
            "session_id": session_id,
            "file_name": "employee_roster_directory",
            "category": "personnel_records",
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    )

    return templates.TemplateResponse(
        request=request,
        name="employees.html",
        context={
            "company_name": COMPANY_NAME,
            "portal_title": PORTAL_TITLE,
            "active_page": "employees",
            "username": sess["username"],
            "role": sess["role"],
            "employees": EMPLOYEES,
        },
    )


@router.get("/api/employees/{emp_id}")
async def get_employee_api(emp_id: str, request: Request):
    """API endpoint to inspect an individual employee profile."""
    session_id = request.cookies.get("apex_session")
    sess = get_session(session_id)
    if not sess:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")

    match = next((e for e in EMPLOYEES if e["id"].lower() == emp_id.lower()), None)
    if not match:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Employee not found")

    return JSONResponse(match)
