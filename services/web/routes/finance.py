"""Financial reports and decoy document download routes."""

from __future__ import annotations

from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from shared.config import settings
from services.web.data.seed_data import (
    COMPANY_NAME,
    PORTAL_TITLE,
    CUSTOMERS,
    INVOICES,
    DECOY_REPORTS,
)
from services.web.security import get_session, log_web_telemetry

router = APIRouter()
templates = Jinja2Templates(directory=str(settings.WEB_BASE_DIR / "templates"))


@router.get("/finance", response_class=HTMLResponse)
async def finance_page(request: Request):
    """Render financial operations, customer ledgers, and decoy document repository."""
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
            "path": "/finance",
            "user_agent": user_agent,
            "session_id": session_id,
            "file_name": "financial_operations_ledger",
            "category": "executive_financials",
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    )

    return templates.TemplateResponse(
        request=request,
        name="finance.html",
        context={
            "company_name": COMPANY_NAME,
            "portal_title": PORTAL_TITLE,
            "active_page": "finance",
            "username": sess["username"],
            "role": sess["role"],
            "customers": CUSTOMERS,
            "invoices": INVOICES,
        },
    )


@router.get("/finance/download/{filename}")
async def download_decoy_report(filename: str, request: Request):
    """Serve simulated confidential decoy financial reports and record exfiltration events."""
    session_id = request.cookies.get("apex_session")
    sess = get_session(session_id)
    if not sess:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    src_ip = request.client.host if request.client else "127.0.0.1"
    src_port = request.client.port if request.client else 0
    user_agent = request.headers.get("user-agent", "Unknown")

    if filename in DECOY_REPORTS:
        report = DECOY_REPORTS[filename]
        # Generate file download event
        log_web_telemetry(
            {
                "eventid": "web.file.download",
                "src_ip": src_ip,
                "src_port": src_port,
                "username": sess["username"],
                "method": "GET",
                "path": f"/finance/download/{filename}",
                "user_agent": user_agent,
                "session_id": session_id,
                "file_name": filename,
                "bytes_transferred": report["size"],
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
        )
        return Response(
            content=report["content"],
            media_type=report["content_type"],
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    # Unknown or suspicious file access attempt
    log_web_telemetry(
        {
            "eventid": "web.suspicious.request",
            "src_ip": src_ip,
            "src_port": src_port,
            "username": sess["username"],
            "method": "GET",
            "path": f"/finance/download/{filename}",
            "user_agent": user_agent,
            "session_id": session_id,
            "reason": f"Attempted download of non-existent or suspicious document: {filename}",
            "attack_vector": "Path Probe / File Enumeration",
            "alert_priority": "MEDIUM",
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    )
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report document not found")
