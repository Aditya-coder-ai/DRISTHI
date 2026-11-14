"""Unit tests for telemetry ingestion adapters."""

from backend.app.integrations.person1_adapter import Person1SecurityEventAdapter
from backend.app.integrations.ssh_adapter import SSHTelemetryAdapter
from backend.app.integrations.ftp_adapter import FTPTelemetryAdapter
from backend.app.schemas.event import SeverityLevel


def test_person1_adapter_ssh_event():
    raw_ssh = {
        "event_id": "ssh-norm-01",
        "asset_id": "ssh-001",
        "event_type": "command_execution",
        "source_ip": "198.51.100.30",
        "source_port": 49152,
        "username": "finance_admin",
        "protocol": "SSH",
        "timestamp": "2026-11-14T03:00:00Z",
        "status": "executed",
        "metadata": {
            "command": "uname -a",
            "session_id": "sess-ssh-4421",
            "password": "ClearTextPasswordShouldBeRedacted",
        },
    }
    adapter = Person1SecurityEventAdapter()
    adapted = adapter.adapt(raw_ssh)

    assert adapted is not None
    assert adapted.event_id == "ssh-norm-01"
    assert adapted.source_service == "ssh"
    assert adapted.asset_id == "ssh-001"
    assert adapted.username == "finance_admin"
    assert adapted.activity.get("command") == "uname -a"
    # Ensure plaintext password was stripped
    assert "password" not in adapted.metadata
    assert adapted.metadata.get("password_length") == len("ClearTextPasswordShouldBeRedacted")


def test_person1_adapter_canary_severity_calculation():
    raw_canary = {
        "asset_id": "db-001",
        "event_type": "canary_triggered",
        "source_ip": "198.51.100.30",
        "protocol": "DATABASE",
        "timestamp": "2026-11-14T03:05:00Z",
        "status": "detected",
        "metadata": {"alert_priority": "HIGH"},
    }
    adapter = Person1SecurityEventAdapter()
    adapted = adapter.adapt(raw_canary)

    assert adapted is not None
    assert adapted.severity == SeverityLevel.CRITICAL.value


def test_ssh_adapter_defaults():
    raw = {
        "event_id": "ssh-01",
        "source_ip": "1.2.3.4",
        "event_type": "login_failed",
    }
    adapter = SSHTelemetryAdapter()
    adapted = adapter.adapt(raw)
    assert adapted.source_service == "ssh"
    assert adapted.asset_id == "ssh-001"


def test_ftp_adapter_defaults():
    raw = {
        "event_id": "ftp-01",
        "source_ip": "1.2.3.4",
        "event_type": "file_download",
    }
    adapter = FTPTelemetryAdapter()
    adapted = adapter.adapt(raw)
    assert adapted.source_service == "ftp"
    assert adapted.asset_id == "ftp-001"

