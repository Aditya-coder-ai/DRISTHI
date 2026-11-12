"""Unit tests for Cowrie SSH Event Adapter."""

from services.ssh.ssh_event_adapter import CowrieSSHAdapter
from shared.event_schema import EventType, EventStatus


def test_normalize_failed_login():
    raw_event = {
        "eventid": "cowrie.login.failed",
        "timestamp": "2026-11-12T15:30:00.123456Z",
        "src_ip": "203.0.113.45",
        "src_port": 49152,
        "session": "abc12345",
        "username": "root",
        "password": "SecretPassword123!",
    }

    event = CowrieSSHAdapter.normalize(raw_event, asset_id="ssh-001")
    assert event is not None
    assert event.asset_id == "ssh-001"
    assert event.protocol == "SSH"
    assert event.event_type == EventType.LOGIN_FAILED.value
    assert event.status == EventStatus.FAILED.value
    assert event.source_ip == "203.0.113.45"
    assert event.source_port == 49152
    assert event.username == "root"
    # Verify password is NOT exposed in plaintext
    assert "SecretPassword123!" not in str(event.metadata)
    assert event.metadata.get("password_length") == len("SecretPassword123!")


def test_normalize_bait_credential_login():
    raw_event = {
        "eventid": "cowrie.login.success",
        "timestamp": "2026-11-12T15:32:00Z",
        "src_ip": "203.0.113.45",
        "src_port": 49152,
        "session": "abc12345",
        "username": "finance_admin",
    }

    event = CowrieSSHAdapter.normalize(raw_event, asset_id="ssh-001")
    assert event is not None
    assert event.event_type == EventType.LOGIN_SUCCESS.value
    assert event.status == EventStatus.SUCCESS.value
    assert event.username == "finance_admin"
    assert event.metadata.get("bait_credential_triggered") is True
    assert event.metadata.get("alert_priority") == "HIGH"


def test_normalize_command_execution():
    raw_event = {
        "eventid": "cowrie.command.input",
        "timestamp": "2026-11-12T15:33:10Z",
        "src_ip": "203.0.113.45",
        "session": "abc12345",
        "input": "cat /etc/passwd",
    }

    event = CowrieSSHAdapter.normalize(raw_event, asset_id="ssh-001")
    assert event is not None
    assert event.event_type == EventType.COMMAND_EXECUTION.value
    assert event.status == EventStatus.EXECUTED.value
    assert event.metadata.get("command") == "cat /etc/passwd"


def test_normalize_file_upload():
    raw_event = {
        "eventid": "cowrie.session.file_upload",
        "timestamp": "2026-11-12T15:35:00Z",
        "src_ip": "203.0.113.45",
        "session": "abc12345",
        "filename": "exploit.sh",
        "shasum": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    }

    event = CowrieSSHAdapter.normalize(raw_event, asset_id="ssh-001")
    assert event is not None
    assert event.event_type == EventType.FILE_UPLOAD.value
    assert event.status == EventStatus.SUCCESS.value
    assert event.metadata.get("filename") == "exploit.sh"
