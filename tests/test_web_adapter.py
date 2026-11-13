"""Unit tests for WebEventAdapter and HTTP event normalization."""

from datetime import datetime, timezone
import pytest

from collector.normalizer import EventNormalizer
from services.web.web_event_adapter import WebEventAdapter
from shared.event_schema import EventStatus, EventType, ProtocolType, SecurityEvent


def test_normalize_failed_login_redaction():
    """Verify failed login events redact passwords to length and calculate attempts."""
    raw = {
        "eventid": "web.login.failed",
        "src_ip": "198.51.100.42",
        "src_port": 54321,
        "username": "admin",
        "password": "SuperSecretPassword123!",
        "repeated_attempts": 2,
        "method": "POST",
        "path": "/login",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "timestamp": "2026-11-13T10:00:00Z",
    }

    event = WebEventAdapter.normalize(raw, asset_id="web-001")
    assert event is not None
    assert event.asset_id == "web-001"
    assert event.protocol == ProtocolType.HTTP.value
    assert event.event_type == EventType.LOGIN_FAILED.value
    assert event.status == EventStatus.FAILED.value
    assert event.username == "admin"
    assert "SuperSecretPassword123!" not in str(event.model_dump())
    assert event.metadata["password_length"] == len("SuperSecretPassword123!")
    assert event.metadata["repeated_attempts"] == 2
    assert "brute_force_detected" not in event.metadata


def test_normalize_brute_force_detection():
    """Verify multiple repeated attempts trigger brute_force_detected flag and HIGH alert."""
    raw = {
        "eventid": "web.login.failed",
        "src_ip": "198.51.100.42",
        "src_port": 54321,
        "username": "administrator",
        "password_length": 8,
        "repeated_attempts": 4,
        "method": "POST",
        "path": "/login",
        "timestamp": "2026-11-13T10:05:00Z",
    }

    event = WebEventAdapter.normalize(raw, asset_id="web-001")
    assert event is not None
    assert event.metadata["brute_force_detected"] is True
    assert event.metadata["alert_priority"] == "HIGH"


def test_normalize_bait_credential_login():
    """Verify successful authentication with bait account sets bait_credential_triggered."""
    raw = {
        "eventid": "web.login.success",
        "src_ip": "203.0.113.19",
        "src_port": 49152,
        "username": "finance_admin",
        "role": "Finance Operations Admin",
        "method": "POST",
        "path": "/login",
        "session_id": "apex_sess_test123",
        "timestamp": "2026-11-13T10:10:00Z",
    }

    event = WebEventAdapter.normalize(raw, asset_id="web-001")
    assert event is not None
    assert event.event_type == EventType.LOGIN_SUCCESS.value
    assert event.status == EventStatus.SUCCESS.value
    assert event.username == "finance_admin"
    assert event.metadata["bait_credential_triggered"] is True
    assert event.metadata["alert_priority"] == "HIGH"


def test_normalize_decoy_report_download():
    """Verify file download telemetry normalizes with file size and path."""
    raw = {
        "eventid": "web.file.download",
        "src_ip": "203.0.113.19",
        "src_port": 49152,
        "username": "finance_admin",
        "file_name": "Q4_consolidated_financials.pdf",
        "bytes_transferred": 18450,
        "path": "/finance/download/Q4_consolidated_financials.pdf",
        "timestamp": "2026-11-13T10:15:00Z",
    }

    event = WebEventAdapter.normalize(raw, asset_id="web-001")
    assert event is not None
    assert event.event_type == EventType.FILE_DOWNLOAD.value
    assert event.status == EventStatus.SUCCESS.value
    assert event.metadata["file_name"] == "Q4_consolidated_financials.pdf"
    assert event.metadata["bytes_transferred"] == 18450


def test_normalize_bait_configuration_trigger():
    """Verify accessing decoy config files triggers BAIT_CREDENTIAL_TRIGGER."""
    raw = {
        "eventid": "web.bait.trigger",
        "src_ip": "203.0.113.19",
        "src_port": 49152,
        "username": "admin",
        "bait_file": "database_config.json",
        "bait_credential_targeted": "database_root",
        "path": "/configuration/view/database_config.json",
        "timestamp": "2026-11-13T10:20:00Z",
    }

    event = WebEventAdapter.normalize(raw, asset_id="web-001")
    assert event is not None
    assert event.event_type == EventType.BAIT_CREDENTIAL_TRIGGER.value
    assert event.status == EventStatus.DETECTED.value
    assert event.metadata["bait_file"] == "database_config.json"
    assert event.metadata["bait_credential_targeted"] == "database_root"
    assert event.metadata["alert_priority"] == "HIGH"


def test_normalize_suspicious_scanner_probe():
    """Verify vulnerability scanner probes normalize to SUSPICIOUS_REQUEST."""
    raw = {
        "eventid": "web.suspicious.request",
        "src_ip": "192.0.2.100",
        "path": "/.env",
        "method": "GET",
        "reason": "Reconnaissance probe targeting restricted path: /.env",
        "attack_vector": "Automated Scanner / Path Traversal",
        "alert_priority": "MEDIUM",
        "timestamp": "2026-11-13T10:25:00Z",
    }

    event = WebEventAdapter.normalize(raw, asset_id="web-001")
    assert event is not None
    assert event.event_type == EventType.SUSPICIOUS_REQUEST.value
    assert event.status == EventStatus.DETECTED.value
    assert event.metadata["path"] == "/.env"
    assert event.metadata["attack_vector"] == "Automated Scanner / Path Traversal"


def test_normalizer_facade_dispatches_http():
    """Verify EventNormalizer correctly delegates HTTP events to WebEventAdapter."""
    raw = {
        "eventid": "web.login.success",
        "src_ip": "10.0.0.5",
        "username": "backup_user",
        "timestamp": "2026-11-13T10:30:00Z",
    }

    event = EventNormalizer.normalize(raw, protocol=ProtocolType.HTTP)
    assert event is not None
    assert event.protocol == "HTTP"
    assert event.username == "backup_user"
    assert event.event_type == EventType.LOGIN_SUCCESS.value

