"""Unified Security Event Schema for Deception Assets.

All decoy services normalize their captured interactions into this standard
schema before feeding into the central event collector and backend.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional
import uuid

from pydantic import BaseModel, Field, field_validator


class ProtocolType(str, Enum):
    SSH = "SSH"
    FTP = "FTP"
    HTTP = "HTTP"
    DATABASE = "DATABASE"
    CUSTOM = "CUSTOM"


class EventStatus(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    ATTEMPT = "attempt"
    EXECUTED = "executed"
    DETECTED = "detected"
    CLOSED = "closed"


class EventType(str, Enum):
    LOGIN_ATTEMPT = "login_attempt"
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    COMMAND_EXECUTION = "command_execution"
    FILE_ACCESS = "file_access"
    FILE_UPLOAD = "file_upload"
    FILE_DOWNLOAD = "file_download"
    SESSION_CONNECT = "session_connect"
    SESSION_DISCONNECT = "session_disconnect"
    QUERY_EXECUTION = "query_execution"
    BAIT_CREDENTIAL_TRIGGER = "bait_credential_trigger"
    SUSPICIOUS_REQUEST = "suspicious_request"


class SecurityEvent(BaseModel):
    """Standardized Security Event model across all deception services."""

    event_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique UUID string for event deduplication and tracking",
    )
    asset_id: str = Field(
        ...,
        description="Identifier of the deception asset (e.g., ssh-001, ftp-001)",
    )
    event_type: str = Field(
        ...,
        description="Classification of event (e.g., login_attempt, command_execution)",
    )
    source_ip: str = Field(
        ...,
        description="Origin IP address of the interaction/attacker",
    )
    source_port: Optional[int] = Field(
        default=None,
        description="Origin port number if available",
    )
    username: Optional[str] = Field(
        default=None,
        description="Username attempted or used during interaction",
    )
    protocol: str = Field(
        ...,
        description="Protocol name: SSH, FTP, HTTP, DATABASE, etc.",
    )
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        description="ISO 8601 UTC timestamp string",
    )
    status: str = Field(
        ...,
        description="Outcome of the interaction (success, failed, executed, etc.)",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Contextual metadata preserving service-specific details safely",
    )

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, v: str) -> str:
        # Verify valid ISO 8601 parseable format
        try:
            # Handle 'Z' suffix
            ts_str = v.replace("Z", "+00:00")
            datetime.fromisoformat(ts_str)
        except Exception as exc:
            raise ValueError(f"Invalid timestamp format '{v}', expected ISO 8601 UTC") from exc
        return v
