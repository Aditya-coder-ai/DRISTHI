"""Integration tests for FTP Deception Honeypot Service."""

import asyncio
import ftplib
import io
import json
from pathlib import Path
import threading
import time
import pytest

from services.ftp.server import FTPServer
from collector.normalizer import EventNormalizer
from shared.config import settings

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TEST_FTP_PORT = 22121
TEST_FTP_HOST = "127.0.0.1"


@pytest.fixture(scope="module")
def running_ftp_server():
    """Start FTPServer on a dedicated test port in a background event loop thread."""
    test_log = PROJECT_ROOT / "var" / "log" / "ftp" / "test_ftp.json"
    test_log.parent.mkdir(parents=True, exist_ok=True)
    if test_log.exists():
        test_log.write_text("", encoding="utf-8")

    server = FTPServer(
        host=TEST_FTP_HOST,
        port=TEST_FTP_PORT,
        log_file=test_log,
    )

    loop = asyncio.new_event_loop()
    thread = threading.Thread(
        target=lambda: loop.run_until_complete(server.serve_forever()),
        daemon=True,
    )
    thread.start()

    # Wait for server to bind and listen
    time.sleep(1.5)

    yield server, test_log

    # Teardown
    loop.call_soon_threadsafe(lambda: asyncio.create_task(server.stop()))
    time.sleep(0.5)


def test_ftp_failed_login(running_ftp_server):
    """Verify that unauthorized login attempt is rejected and logged."""
    server, test_log = running_ftp_server
    ftp = ftplib.FTP()
    ftp.connect(TEST_FTP_HOST, TEST_FTP_PORT, timeout=5)

    with pytest.raises(ftplib.error_perm) as excinfo:
        ftp.login("unauthorized_user", "BadPassword123!")
    assert "530" in str(excinfo.value)

    ftp.close()
    time.sleep(0.5)

    # Verify event logged
    events = []
    with open(test_log, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                ev = EventNormalizer.normalize(json.loads(line.strip()), protocol="FTP")
                if ev:
                    events.append(ev)

    failed_events = [e for e in events if e.event_type == "login_failed" and e.username == "unauthorized_user"]
    assert len(failed_events) >= 1
    fe = failed_events[0]
    assert fe.asset_id == "ftp-001"
    assert fe.status == "failed"
    assert "BadPassword123!" not in str(fe.metadata)
    assert fe.metadata.get("password_length") == len("BadPassword123!")


def test_ftp_successful_bait_login_and_operations(running_ftp_server):
    """Verify bait credential login, directory listing, file transfers, and traversal blocking."""
    server, test_log = running_ftp_server
    ftp = ftplib.FTP()
    ftp.connect(TEST_FTP_HOST, TEST_FTP_PORT, timeout=5)

    # 1. Login with bait credential
    ftp.login("backup_user", "Backup@2026")
    curr_dir = ftp.pwd()
    assert curr_dir == "/backups/finance"

    # 2. Directory Listing
    files = ftp.nlst()
    assert "customer_database.sql" in files
    assert "backup.zip" in files
    assert "db_migration_notes.txt" in files

    # 3. File Download (customer_database.sql)
    sql_buf = io.BytesIO()
    ftp.retrbinary("RETR customer_database.sql", sql_buf.write)
    sql_text = sql_buf.getvalue().decode("utf-8")
    assert "corp_finance_db" in sql_text
    assert "Apex Global Logistics" in sql_text

    # 4. Navigate to /corporate and download employee_records.csv
    ftp.cwd("/corporate")
    assert ftp.pwd() == "/corporate"
    corp_files = ftp.nlst()
    assert "employee_records.csv" in corp_files
    assert "financial_report.xlsx" in corp_files

    csv_buf = io.BytesIO()
    ftp.retrbinary("RETR employee_records.csv", csv_buf.write)
    csv_text = csv_buf.getvalue().decode("utf-8")
    assert "John,Doe" in csv_text

    # 5. File Upload (STOR)
    payload_data = b"#!/bin/bash\necho 'simulated test payload'\n"
    ftp.storbinary("STOR test_probe.sh", io.BytesIO(payload_data))

    # Verify uploaded file appears in directory
    assert "test_probe.sh" in ftp.nlst()

    # 6. Attempt Path Traversal Escape
    with pytest.raises(ftplib.error_perm) as excinfo:
        ftp.cwd("../../../../../Windows")
    assert "550" in str(excinfo.value)

    with pytest.raises(ftplib.error_perm) as excinfo:
        trap_buf = io.BytesIO()
        ftp.retrbinary("RETR ../../../etc/passwd", trap_buf.write)
    assert "550" in str(excinfo.value)

    # 7. Attempt Restricted Deletion
    with pytest.raises(ftplib.error_perm) as excinfo:
        ftp.delete("employee_records.csv")
    assert "550" in str(excinfo.value)

    ftp.quit()
    time.sleep(1)

    # Verify logged and normalized security events
    events = []
    with open(test_log, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                ev = EventNormalizer.normalize(json.loads(line.strip()), protocol="FTP")
                if ev:
                    events.append(ev)

    # Verify login_success with bait alert
    success_events = [e for e in events if e.event_type == "login_success" and e.username == "backup_user"]
    assert len(success_events) >= 1
    assert success_events[0].metadata.get("bait_credential_triggered") is True
    assert success_events[0].metadata.get("alert_priority") == "HIGH"

    # Verify file_download events
    download_events = [e for e in events if e.event_type == "file_download"]
    downloaded_names = [e.metadata.get("filename") for e in download_events]
    assert "customer_database.sql" in downloaded_names
    assert "employee_records.csv" in downloaded_names

    # Verify file_upload event
    upload_events = [e for e in events if e.event_type == "file_upload"]
    assert len(upload_events) >= 1
    assert upload_events[0].metadata.get("filename") == "test_probe.sh"

    # Verify suspicious_request events for traversal & deletion
    suspicious_events = [e for e in events if e.event_type == "suspicious_request"]
    assert len(suspicious_events) >= 1

    # Verify all events conform to SecurityEvent schema
    for ev in events:
        assert ev.asset_id == "ftp-001"
        assert ev.protocol == "FTP"
        assert ev.event_id is not None
        assert ev.timestamp.endswith("Z")

