"""Integration tests for the Web Admin Deception Portal."""

import pytest
from starlette.testclient import TestClient

from collector.event_collector import global_collector
from services.web.app import app
from services.web.security import ACTIVE_SESSIONS, LOGIN_ATTEMPTS
from shared.event_schema import EventType


@pytest.fixture(autouse=True)
def clean_test_state():
    """Clear memory stores before each test."""
    global_collector.clear()
    ACTIVE_SESSIONS.clear()
    LOGIN_ATTEMPTS.clear()
    yield
    global_collector.clear()
    ACTIVE_SESSIONS.clear()
    LOGIN_ATTEMPTS.clear()


@pytest.fixture
def client():
    """Create test client with cookies support."""
    return TestClient(app, raise_server_exceptions=True)


def test_login_page_renders(client):
    """Test that login page loads properly."""
    response = client.get("/login")
    assert response.status_code == 200
    assert "Apex Internal Management System" in response.text
    assert "Apex Financial Group" in response.text
    assert '<input type="password"' in response.text


def test_unauthenticated_redirect(client):
    """Test that protected pages redirect unauthenticated requests to /login."""
    for path in ["/", "/dashboard", "/employees", "/finance", "/database", "/configuration"]:
        response = client.get(path, follow_redirects=False)
        assert response.status_code in (302, 303, 307)
        assert "/login" in response.headers.get("location", "")


def test_failed_login_redacts_password_and_logs_event(client):
    """Test failed authentication captures event with redacted password."""
    response = client.post(
        "/login",
        data={"username": "administrator", "password": "SuperSecretPassword123!"},
    )
    assert response.status_code == 401
    assert "Invalid corporate credentials" in response.text

    # Verify event was captured
    events = global_collector.get_all()
    failed_events = [e for e in events if e.event_type == EventType.LOGIN_FAILED.value]
    assert len(failed_events) >= 1
    event = failed_events[0]
    assert event.username == "administrator"
    assert event.metadata["password_length"] == len("SuperSecretPassword123!")
    # Plaintext password must NOT appear anywhere in event
    assert "SuperSecretPassword123!" not in str(event.model_dump())


def test_brute_force_detection(client):
    """Test that 3 or more failed attempts flag brute force."""
    for i in range(3):
        client.post(
            "/login",
            data={"username": "admin", "password": f"WrongAttempt{i}"},
        )

    events = global_collector.get_by_type(EventType.LOGIN_FAILED.value)
    assert len(events) == 3
    third_event = events[2]
    assert third_event.metadata.get("brute_force_detected") is True
    assert third_event.metadata.get("alert_priority") == "HIGH"


def test_successful_bait_login_sets_cookie(client):
    """Test successful authentication with bait credential sets session and emits event."""
    response = client.post(
        "/login",
        data={"username": "finance_admin", "password": "Finance@2026"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers.get("location") == "/dashboard"
    assert "apex_session" in response.cookies

    # Verify telemetry
    success_events = global_collector.get_by_type(EventType.LOGIN_SUCCESS.value)
    assert len(success_events) == 1
    event = success_events[0]
    assert event.username == "finance_admin"
    assert event.metadata.get("bait_credential_triggered") is True
    assert event.metadata.get("alert_priority") == "HIGH"


def test_authenticated_dashboard_and_employees(client):
    """Test accessing dashboard and employee directory when authenticated."""
    # Login first
    client.post(
        "/login",
        data={"username": "admin", "password": "Apex@2026!"},
    )

    # Access dashboard
    dash_resp = client.get("/dashboard")
    assert dash_resp.status_code == 200
    assert "Executive Operations Dashboard" in dash_resp.text
    assert "Recent Operations &amp; Audit Trail" in dash_resp.text

    # Access employees
    emp_resp = client.get("/employees")
    assert emp_resp.status_code == 200
    assert "Employee Directory" in emp_resp.text
    assert "John Doe" in emp_resp.text
    assert "jdoe@apexfinancial.corp" in emp_resp.text

    # Test individual employee API
    api_resp = client.get("/api/employees/EMP-1001")
    assert api_resp.status_code == 200
    emp_data = api_resp.json()
    assert emp_data["name"] == "John Doe"
    assert emp_data["department"] == "Finance & Accounting"


def test_decoy_report_download(client):
    """Test downloading confidential decoy reports and event generation."""
    client.post(
        "/login",
        data={"username": "finance_admin", "password": "Finance@2026"},
    )

    # Download PDF
    pdf_resp = client.get("/finance/download/Q4_consolidated_financials.pdf")
    assert pdf_resp.status_code == 200
    assert pdf_resp.headers["content-type"] == "application/pdf"
    assert b"%PDF-1.4" in pdf_resp.content

    # Download XLSX
    xlsx_resp = client.get("/finance/download/payroll_tax_filing_2026.xlsx")
    assert xlsx_resp.status_code == 200
    assert len(xlsx_resp.content) > 0

    # Verify download event
    download_events = global_collector.get_by_type(EventType.FILE_DOWNLOAD.value)
    assert len(download_events) >= 2
    assert any(e.metadata.get("file_name") == "Q4_consolidated_financials.pdf" for e in download_events)


def test_safe_database_query_console(client):
    """Test safe simulated query execution in the SQL console."""
    client.post(
        "/login",
        data={"username": "database_root", "password": "DBroot@2026"},
    )

    # Post query
    resp = client.post(
        "/database/query",
        data={"query": "SELECT * FROM customers WHERE tier = 'Enterprise';"},
    )
    assert resp.status_code == 200
    assert "Query Result" in resp.text
    assert "Apex Global Logistics" in resp.text

    # Verify query execution event
    query_events = global_collector.get_by_type(EventType.QUERY_EXECUTION.value)
    assert len(query_events) == 1
    assert query_events[0].metadata["query"] == "SELECT * FROM customers WHERE tier = 'Enterprise';"
    assert query_events[0].metadata["simulated_table"] == "customers"


def test_view_bait_configuration_file(client):
    """Test viewing decoy config triggers BAIT_CREDENTIAL_TRIGGER."""
    client.post(
        "/login",
        data={"username": "admin", "password": "Apex@2026!"},
    )

    cfg_resp = client.get("/configuration/view/database_config.json")
    assert cfg_resp.status_code == 200
    assert "database_root" in cfg_resp.text
    assert "DBroot@2026" in cfg_resp.text

    # Verify bait trigger event
    bait_events = global_collector.get_by_type(EventType.BAIT_CREDENTIAL_TRIGGER.value)
    assert len(bait_events) == 1
    event = bait_events[0]
    assert event.metadata["bait_file"] == "database_config.json"
    assert event.metadata["bait_credential_targeted"] == "database_root"
    assert event.metadata["alert_priority"] == "HIGH"


def test_suspicious_scanner_probes_blocked_and_logged(client):
    """Test scanner probe paths (.env, /wp-admin, path traversal) trigger suspicious request events."""
    for probe in ["/.env", "/wp-admin", "/phpmyadmin", "/static/../../etc/passwd"]:
        resp = client.get(probe)
        assert resp.status_code == 404

    suspicious_events = global_collector.get_by_type(EventType.SUSPICIOUS_REQUEST.value)
    assert len(suspicious_events) >= 4


def test_logout_terminates_session(client):
    """Test logout invalidates session and redirects to login."""
    client.post(
        "/login",
        data={"username": "admin", "password": "Apex@2026!"},
    )

    # Ensure authenticated access works
    assert client.get("/dashboard", follow_redirects=False).status_code == 200

    # Logout
    logout_resp = client.get("/logout", follow_redirects=False)
    assert logout_resp.status_code == 303
    assert logout_resp.headers["location"] == "/login"

    # Subsequent access redirected
    dash_after = client.get("/dashboard", follow_redirects=False)
    assert dash_after.status_code == 303
