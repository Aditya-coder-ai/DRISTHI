"""Web Admin Portal Deception Event Adapter.

Normalizes HTTP web interaction telemetry into unified SecurityEvent instances.
Redacts cleartext passwords and tags bait credential triggers with HIGH alert priority.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any, Dict, Optional

from shared.event_schema import SecurityEvent, EventType, EventStatus, ProtocolType
from shared.config import settings


class WebEventAdapter:
    """Normalizes raw web portal telemetry into standard SecurityEvent instances."""

    EVENT_MAP = {
        "web.login.attempt": (EventType.LOGIN_ATTEMPT.value, EventStatus.ATTEMPT.value),
        "web.login.failed": (EventType.LOGIN_FAILED.value, EventStatus.FAILED.value),
        "web.login.success": (EventType.LOGIN_SUCCESS.value, EventStatus.SUCCESS.value),
        "web.file.access": (EventType.FILE_ACCESS.value, EventStatus.EXECUTED.value),
        "web.file.download": (EventType.FILE_DOWNLOAD.value, EventStatus.SUCCESS.value),
        "web.suspicious.request": (EventType.SUSPICIOUS_REQUEST.value, EventStatus.DETECTED.value),
        "web.bait.trigger": (EventType.BAIT_CREDENTIAL_TRIGGER.value, EventStatus.DETECTED.value),
        "web.query.execution": (EventType.QUERY_EXECUTION.value, EventStatus.EXECUTED.value),
    }

    @staticmethod
    def _format_timestamp(raw_ts: Optional[str]) -> str:
        if not raw_ts:
            return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            cleaned = raw_ts.replace("Z", "+00:00")
            dt = datetime.fromisoformat(cleaned)
            return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    @classmethod
    def normalize(cls, raw: Dict[str, Any], asset_id: Optional[str] = None) -> Optional[SecurityEvent]:
        raw_eventid = raw.get("eventid")
        if not raw_eventid or raw_eventid not in cls.EVENT_MAP:
            return None

        event_type, status = cls.EVENT_MAP[raw_eventid]
        src_ip = raw.get("src_ip", "127.0.0.1")
        src_port = raw.get("src_port")
        username = raw.get("username")
        timestamp = cls._format_timestamp(raw.get("timestamp"))

        # Base metadata
        metadata: Dict[str, Any] = {
            "method": raw.get("method", "GET"),
            "path": raw.get("path", "/"),
            "user_agent": raw.get("user_agent", "Unknown"),
            "session_id": raw.get("session_id"),
            "portal": "Apex Internal Management System",
        }

        # Specific mappings
        if raw_eventid == "web.login.failed":
            pwd = raw.get("password")
            metadata["password_length"] = len(pwd) if pwd is not None else raw.get("password_length", 0)
            metadata["repeated_attempts"] = raw.get("repeated_attempts", 1)
            if raw.get("repeated_attempts", 1) >= 3:
                metadata["brute_force_detected"] = True
                metadata["alert_priority"] = "HIGH"

        elif raw_eventid == "web.login.success":
            metadata["authenticated_role"] = raw.get("role", "Administrator")
            if username in ("admin", "finance_admin", "backup_user"):
                metadata["bait_credential_triggered"] = True
                metadata["alert_priority"] = "HIGH"

        elif raw_eventid == "web.file.access":
            metadata["file_name"] = raw.get("file_name")
            metadata["category"] = raw.get("category", "decoy_document")

        elif raw_eventid == "web.file.download":
            metadata["file_name"] = raw.get("file_name")
            metadata["bytes_transferred"] = raw.get("bytes_transferred", 0)

        elif raw_eventid == "web.bait.trigger":
            metadata["bait_file"] = raw.get("bait_file")
            metadata["bait_credential_targeted"] = raw.get("bait_credential_targeted")
            metadata["alert_priority"] = "HIGH"

        elif raw_eventid == "web.suspicious.request":
            metadata["reason"] = raw.get("reason", "Suspicious URL or parameter access")
            metadata["attack_vector"] = raw.get("attack_vector", "Reconnaissance / Probe")
            metadata["alert_priority"] = raw.get("alert_priority", "MEDIUM")

        elif raw_eventid == "web.query.execution":
            metadata["query"] = raw.get("query")
            metadata["simulated_table"] = raw.get("table")

        return SecurityEvent(
            asset_id=asset_id or "web-001",
            event_type=event_type,
            source_ip=src_ip,
            source_port=src_port,
            username=username,
            protocol=ProtocolType.HTTP.value,
            timestamp=timestamp,
            status=status,
            metadata=metadata,
        )

    @classmethod
    def normalize_json_line(cls, line: str, asset_id: Optional[str] = None) -> Optional[SecurityEvent]:
        try:
            data = json.loads(line.strip())
            return cls.normalize(data, asset_id=asset_id)
        except Exception:
            return None
