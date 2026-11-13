"""Unit tests for FTP Deception Event Adapter."""

from services.ftp.ftp_event_adapter import FTPEventAdapter
from shared.event_schema import EventType, EventStatus


def test_normalize_failed_ftp_login():
    raw_event = {
        "eventid": "ftp.login.failed",
        "timestamp": "2026-11-13T10:00:00Z",
        "src_ip": "198.51.100.22",
        "src_port": 51234,
        "session_id": "sess_001",
        "username": "intruder",
        "password": "CleartextPassword!",
    }

    event = FTPEventAdapter.normalize(raw_event, asset_id="ftp-001")
    assert event is not None
    assert event.asset_id == "ftp-001"
    assert event.protocol == "FTP"
    assert event.event_type == EventType.LOGIN_FAILED.value
    assert event.status == EventStatus.FAILED.value
    assert event.source_ip == "198.51.100.22"
    assert event.username == "intruder"
    # Ensure cleartext password is not exposed
    assert "CleartextPassword!" not in str(event.metadata)
    assert event.metadata.get("password_length") == len("CleartextPassword!")


def test_normalize_bait_credential_login():
    raw_event = {
        "eventid": "ftp.login.success",
        "timestamp": "2026-11-13T10:05:00Z",
        "src_ip": "198.51.100.22",
        "src_port": 51234,
        "session_id": "sess_001",
        "username": "backup_user",
    }

    event = FTPEventAdapter.normalize(raw_event, asset_id="ftp-001")
    assert event is not None
    assert event.event_type == EventType.LOGIN_SUCCESS.value
    assert event.status == EventStatus.SUCCESS.value
    assert event.username == "backup_user"
    assert event.metadata.get("bait_credential_triggered") is True
    assert event.metadata.get("alert_priority") == "HIGH"


def test_normalize_ftp_directory_list():
    raw_event = {
        "eventid": "ftp.directory.list",
        "timestamp": "2026-11-13T10:06:00Z",
        "src_ip": "198.51.100.22",
        "session_id": "sess_001",
        "username": "backup_user",
        "path": "/backups/finance",
    }

    event = FTPEventAdapter.normalize(raw_event, asset_id="ftp-001")
    assert event is not None
    assert event.event_type == EventType.FILE_ACCESS.value
    assert event.status == EventStatus.EXECUTED.value
    assert event.metadata.get("action") == "directory_listing"
    assert event.metadata.get("path") == "/backups/finance"


def test_normalize_ftp_file_download():
    raw_event = {
        "eventid": "ftp.file.download",
        "timestamp": "2026-11-13T10:07:00Z",
        "src_ip": "198.51.100.22",
        "session_id": "sess_001",
        "username": "backup_user",
        "path": "/backups/finance/customer_database.sql",
        "filename": "customer_database.sql",
        "bytes_transferred": 2048,
    }

    event = FTPEventAdapter.normalize(raw_event, asset_id="ftp-001")
    assert event is not None
    assert event.event_type == EventType.FILE_DOWNLOAD.value
    assert event.status == EventStatus.SUCCESS.value
    assert event.metadata.get("filename") == "customer_database.sql"
    assert event.metadata.get("bytes_transferred") == 2048


def test_normalize_ftp_suspicious_request():
    raw_event = {
        "eventid": "ftp.suspicious.request",
        "timestamp": "2026-11-13T10:08:00Z",
        "src_ip": "198.51.100.22",
        "session_id": "sess_001",
        "username": "backup_user",
        "command": "CWD",
        "argument": "../../../../../Windows",
        "reason": "Directory traversal attempt detected",
    }

    event = FTPEventAdapter.normalize(raw_event, asset_id="ftp-001")
    assert event is not None
    assert event.event_type == EventType.SUSPICIOUS_REQUEST.value
    assert event.status == EventStatus.DETECTED.value
    assert event.metadata.get("command") == "CWD"
    assert event.metadata.get("alert_priority") == "MEDIUM"
