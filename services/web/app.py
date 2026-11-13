"""Apex Internal Management System - Web Admin Deception Portal.

A realistic corporate administration honeypot simulating Apex Financial Group's
internal operations infrastructure to detect, log, and analyze unauthorized activity.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from fastapi import FastAPI, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from shared.config import settings
from shared.logger import get_logger
from services.web.routes import (
    auth,
    dashboard,
    employees,
    finance,
    database,
    configuration,
)
from services.web.security import log_web_telemetry

logger = get_logger("WebApp")

SUSPICIOUS_PATH_PATTERNS = [
    ".env",
    "wp-admin",
    "wp-login",
    "phpmyadmin",
    ".git",
    "xmlrpc.php",
    "admin.php",
    "config.php",
    "shell.php",
    "passwd",
    "web.config",
    ".aws",
    ".ssh",
    "actuator",
    "swagger",
    "api-docs",
]

# Create FastAPI application
app = FastAPI(
    title=settings.WEB_PORTAL_NAME,
    description="Apex Financial Group Internal Administration Infrastructure",
    version="2.4.1",
    docs_url=None,  # Conceal standard API documentation to mimic proprietary internal portal
    redoc_url=None,
    openapi_url=None,
)

# Mount static assets
static_dir = settings.WEB_BASE_DIR / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


@app.middleware("http")
async def monitor_request_telemetry(request: Request, call_next):
    """Intercept all incoming requests to identify scanning, reconnaissance, and directory traversal."""
    path = request.url.path
    path_lower = path.lower()
    src_ip = request.client.host if request.client else "127.0.0.1"
    src_port = request.client.port if request.client else 0
    user_agent = request.headers.get("user-agent", "Unknown")
    session_id = request.cookies.get("apex_session")

    # Detect suspicious reconnaissance probes and directory traversal
    is_suspicious = any(pat in path_lower for pat in SUSPICIOUS_PATH_PATTERNS) or ".." in path
    if is_suspicious:
        log_web_telemetry(
            {
                "eventid": "web.suspicious.request",
                "src_ip": src_ip,
                "src_port": src_port,
                "username": None,
                "method": request.method,
                "path": path,
                "user_agent": user_agent,
                "session_id": session_id,
                "reason": f"Reconnaissance probe targeting restricted path or vulnerability signature: {path}",
                "attack_vector": "Automated Scanner / Path Traversal",
                "alert_priority": "MEDIUM",
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
        )
        return PlainTextResponse(
            "404 Not Found - The requested resource does not exist on this server.\n"
            "Unauthorized access attempts are logged and forwarded to Information Security.",
            status_code=status.HTTP_404_NOT_FOUND,
        )

    # Continue normal request processing
    response = await call_next(request)
    return response


# Include modular route handlers
app.include_router(auth.router)
app.include_router(dashboard.router)
app.include_router(employees.router)
app.include_router(finance.router)
app.include_router(database.router)
app.include_router(configuration.router)


@app.exception_handler(404)
async def custom_404_handler(request: Request, exc):
    """Log unmapped endpoint accesses as suspicious probe activity."""
    src_ip = request.client.host if request.client else "127.0.0.1"
    src_port = request.client.port if request.client else 0
    user_agent = request.headers.get("user-agent", "Unknown")

    log_web_telemetry(
        {
            "eventid": "web.suspicious.request",
            "src_ip": src_ip,
            "src_port": src_port,
            "username": None,
            "method": request.method,
            "path": request.url.path,
            "user_agent": user_agent,
            "reason": f"Endpoint enumeration / 404 access to undefined path: {request.url.path}",
            "attack_vector": "Web Enumeration",
            "alert_priority": "LOW",
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    )
    return HTMLResponse(
        """
        <!DOCTYPE html>
        <html>
        <head><title>404 Not Found &bull; Apex Financial Group</title></head>
        <body style="background: #0b1120; color: #f8fafc; font-family: sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0;">
          <div style="text-align: center; max-width: 500px; padding: 40px; background: #1e293b; border-radius: 8px; border: 1px solid #334155;">
            <h1 style="color: #ef4444; margin-top: 0;">404 &bull; Resource Not Found</h1>
            <p style="color: #94a3b8; font-size: 14px; line-height: 1.6;">
              The administrative endpoint you requested could not be located. Your session and IP address have been logged.
            </p>
            <a href="/login" style="display: inline-block; margin-top: 16px; padding: 8px 16px; background: #2563eb; color: white; text-decoration: none; border-radius: 4px; font-size: 13px;">Return to Portal</a>
          </div>
        </body>
        </html>
        """,
        status_code=status.HTTP_404_NOT_FOUND,
    )
