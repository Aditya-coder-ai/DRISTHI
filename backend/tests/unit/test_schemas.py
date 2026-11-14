"""Unit tests for Pydantic event and telemetry schemas."""

from datetime import datetime, timezone
import pytest
from backend.app.schemas.event import AttackEventCreate, SeverityLevel, IngestionResponse


def test_attack_event_create_valid():
    evt = AttackEventCreate(
        event_id="test-evt-001",
        source_ip="192.168.1.50",
        source_service="ssh",
        asset_id="ssh-001",
        event_type="command_execution",
        username="admin",
        severity=SeverityLevel.HIGH.value,
        status="executed",
        timestamp="2026-11-14T10:00:00Z",
        activity={"command": "whoami"},
        metadata={"session_id": "sess-1"},
    )
    assert evt.event_id == "test-evt-001"
    assert evt.source_ip == "192.168.1.50"
    assert evt.severity == "high"
    assert evt.timestamp.tzinfo is not None


def test_attack_event_timestamp_string_conversion():
    evt = AttackEventCreate(
        source_ip="10.0.0.1",
        source_service="ftp",
        asset_id="ftp-001",
        event_type="login_failed",
        timestamp="2026-11-14T12:30:00Z",
    )
    assert isinstance(evt.timestamp, datetime)
    assert evt.timestamp == datetime(2026, 11, 14, 12, 30, 0, tzinfo=timezone.utc)


def test_attack_event_invalid_timestamp():
    with pytest.raises(ValueError):
        AttackEventCreate(
            source_ip="10.0.0.1",
            source_service="ftp",
            asset_id="ftp-001",
            event_type="login_failed",
            timestamp="not-a-timestamp",
        )


def test_ingestion_response_serialization():
    resp = IngestionResponse(
        status="success",
        processed=5,
        persisted=5,
        duplicates_skipped=0,
        errors=[],
    )
    data = resp.model_dump()
    assert data["status"] == "success"
    assert data["processed"] == 5
    assert data["duplicates_skipped"] == 0

