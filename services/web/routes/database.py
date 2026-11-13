"""Database management and safe query simulation routes."""

from __future__ import annotations

from datetime import datetime, timezone
from fastapi import APIRouter, Form, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from shared.config import settings
from services.web.data.seed_data import (
    COMPANY_NAME,
    PORTAL_TITLE,
    EMPLOYEES,
    CUSTOMERS,
    INVOICES,
)
from services.web.security import get_session, log_web_telemetry

router = APIRouter()
templates = Jinja2Templates(directory=str(settings.WEB_BASE_DIR / "templates"))


@router.get("/database", response_class=HTMLResponse)
async def database_page(request: Request):
    """Render database cluster status and interactive query console."""
    session_id = request.cookies.get("apex_session")
    sess = get_session(session_id)
    if not sess:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    return templates.TemplateResponse(
        request=request,
        name="database.html",
        context={
            "company_name": COMPANY_NAME,
            "portal_title": PORTAL_TITLE,
            "active_page": "database",
            "username": sess["username"],
            "role": sess["role"],
            "query": "SELECT * FROM customers LIMIT 5;",
            "query_result": False,
        },
    )


@router.post("/database/query", response_class=HTMLResponse)
async def execute_query(request: Request, query: str = Form(...)):
    """Simulate execution of SQL queries in a safe, isolated in-memory sandbox."""
    session_id = request.cookies.get("apex_session")
    sess = get_session(session_id)
    if not sess:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    src_ip = request.client.host if request.client else "127.0.0.1"
    src_port = request.client.port if request.client else 0
    user_agent = request.headers.get("user-agent", "Unknown")

    clean_query = query.strip()
    lower_query = clean_query.lower()

    # Determine simulated dataset
    if "employee" in lower_query or "emp" in lower_query:
        table_name = "employees"
        columns = ["id", "name", "department", "designation", "email"]
        rows = [
            [e["id"], e["name"], e["department"], e["designation"], e["email"]]
            for e in EMPLOYEES
        ]
    elif "customer" in lower_query or "cust" in lower_query:
        table_name = "customers"
        columns = ["id", "name", "tier", "balance", "status"]
        rows = [
            [c["id"], c["name"], c["tier"], f"${c['balance']:,.2f}", c["status"]]
            for c in CUSTOMERS
        ]
    elif "invoice" in lower_query or "inv" in lower_query:
        table_name = "invoices"
        columns = ["id", "customer", "amount", "status", "date"]
        rows = [
            [i["id"], i["customer"], i["amount"], i["status"], i["date"]]
            for i in INVOICES
        ]
    else:
        table_name = "system"
        columns = ["execution_status", "message"]
        rows = [["SUCCESS", "Query executed safely against simulated sandbox database. 0 rows affected."]]

    # Log query execution event
    log_web_telemetry(
        {
            "eventid": "web.query.execution",
            "src_ip": src_ip,
            "src_port": src_port,
            "username": sess["username"],
            "method": "POST",
            "path": "/database/query",
            "user_agent": user_agent,
            "session_id": session_id,
            "query": clean_query,
            "table": table_name,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    )

    return templates.TemplateResponse(
        request=request,
        name="database.html",
        context={
            "company_name": COMPANY_NAME,
            "portal_title": PORTAL_TITLE,
            "active_page": "database",
            "username": sess["username"],
            "role": sess["role"],
            "query": clean_query,
            "query_result": True,
            "query_columns": columns,
            "query_rows": rows,
        },
    )
