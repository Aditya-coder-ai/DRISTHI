"""Unit tests for Unified Security Event Schema."""

import json
import pytest
from pydantic import ValidationError

from shared.event_schema import SecurityEvent, EventType, EventStatus, ProtocolType


def test_security_event_creation_valid():
    """Verify that a valid SecurityEvent passes schema validation."""
    event = SecurityEvent(
        asset_id="ssh-001",
        event_type=EventType.LOGIN_ATTEMPT.value,
        source_ip="192.0.2.10",
        source_port=54321,
        username="finance_admin",
        protocol=ProtocolType.SSH.value,
        timestamp="2026-11-12T15:30:00Z",
        status=EventStatus.FAILED.value,
        metadata={"hostname": "finance-server"},
    )

    assert event.event_id is not None
    assert event.asset_id == "ssh-001"
    assert event.protocol == "SSH"
    assert event.status == "failed"
    assert event.metadata["hostname"] == "finance-server"


def test_security_event_invalid_timestamp():
    """Verify that malformed timestamp raises a ValidationError."""
    with pytest.raises(ValidationError):
        SecurityEvent(
            asset_id="ssh-001",
            event_type="login_attempt",
            source_ip="192.0.2.10",
            protocol="SSH",
            timestamp="NOT_A_TIMESTAMP",
            status="failed",
        )


def test_security_event_json_serialization():
    """Verify serialization to JSON adheres to Person 1 - Person 2 schema contract."""
    event = SecurityEvent(
        asset_id="ssh-001",
        event_type="login_attempt",
        source_ip="192.0.2.10",
        username="finance_admin",
        protocol="SSH",
        timestamp="2026-11-12T15:30:00Z",
        status="failed",
        metadata={"hostname": "finance-server"},
    )

    json_str = event.model_dump_json()
    data = json.loads(json_str)

    required_keys = [
        "event_id",
        "asset_id",
        "event_type",
        "source_ip",
        "username",
        "protocol",
        "timestamp",
        "status",
        "metadata",
    ]
    for key in required_keys:
        assert key in data, f"Missing required key in JSON output: {key}"

    assert data["asset_id"] == "ssh-001"
    assert data["source_ip"] == "192.0.2.10"
    assert data["metadata"]["hostname"] == "finance-server"

