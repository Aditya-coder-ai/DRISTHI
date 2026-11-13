"""Authentication route handlers for Apex Web Admin Portal."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Form, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from shared.config import settings
from shared.logger import get_logger
from services.web.data.seed_data import COMPANY_NAME, PORTAL_TITLE
from services.web.security import (
    create_session,
    delete_session,
    get_session,
    log_web_telemetry,
    record_login_attempt,
    reset_login_attempts,
)

logger = get_logger("WebAuth")
router = APIRouter()
templates = Jinja2Templates(directory=str(settings.WEB_BASE_DIR / "templates"))

# Fictional credential registry for honeypot interaction
# Includes bait credentials matching SSH and FTP configurations
VALID_CREDENTIALS = {
    "admin": {"password": "Apex@2026!", "role": "Senior Administrator"},
    "administrator": {"password": "Admin@2026", "role": "Senior Administrator"},
    "finance_admin": {"password": "Finance@2026", "role": "Finance Operations Admin"},
    "backup_user": {"password": "Backup@2026", "role": "Storage Systems Engineer"},
    "database_root": {"password": "DBroot@2026", "role": "Database Administrator"},
}


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Render the corporate admin portal login page."""
    session_id = request.cookies.get("apex_session")
    if get_session(session_id):
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)

    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "company_name": COMPANY_NAME,
            "portal_title": PORTAL_TITLE,
            "error": None,
        },
    )


@router.post("/login", response_class=HTMLResponse)
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    remember: Optional[str] = Form(None),
):
    """Handle administrative login submissions and generate security telemetry."""
    src_ip = request.client.host if request.client else "127.0.0.1"
    src_port = request.client.port if request.client else 0
    user_agent = request.headers.get("user-agent", "Unknown")
    clean_user = username.strip()

    # Track attempts for brute-force analysis
    attempt_count = record_login_attempt(src_ip, clean_user)
    is_brute_force = attempt_count >= 3

    # Check credentials
    cred_info = VALID_CREDENTIALS.get(clean_user)
    if cred_info and cred_info["password"] == password:
        # Successful authentication
        reset_login_attempts(src_ip, clean_user)
        session_id = create_session(clean_user, role=cred_info["role"])

        # Log success event (passwords never logged)
        log_web_telemetry(
            {
                "eventid": "web.login.success",
                "src_ip": src_ip,
                "src_port": src_port,
                "username": clean_user,
                "role": cred_info["role"],
                "method": "POST",
                "path": "/login",
                "user_agent": user_agent,
                "session_id": session_id,
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
        )

        response = RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)
        # Set session cookie
        max_age = 86400 * 30 if remember else 3600
        response.set_cookie(
            key="apex_session",
            value=session_id,
            max_age=max_age,
            httponly=True,
            samesite="lax",
        )
        return response

    # Failed authentication
    # CRITICAL: Never log cleartext password. Redact to password length only.
    log_web_telemetry(
        {
            "eventid": "web.login.failed",
            "src_ip": src_ip,
            "src_port": src_port,
            "username": clean_user,
            "password_length": len(password),
            "repeated_attempts": attempt_count,
            "method": "POST",
            "path": "/login",
            "user_agent": user_agent,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    )

    error_msg = "Invalid corporate credentials. Account interaction has been logged."
    if is_brute_force:
        error_msg = f"Security Alert: Multiple failed attempts ({attempt_count}). Remote IP flagged for security review."

    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "company_name": COMPANY_NAME,
            "portal_title": PORTAL_TITLE,
            "error": error_msg,
            "username": clean_user,
        },
        status_code=status.HTTP_401_UNAUTHORIZED,
    )


@router.get("/logout")
async def logout(request: Request):
    """Terminate the active management session."""
    session_id = request.cookies.get("apex_session")
    delete_session(session_id)
    response = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(key="apex_session")
    return response
