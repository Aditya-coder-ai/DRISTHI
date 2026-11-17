"""Cowrie SSH Event Adapter.

Extracts raw event dictionaries from Cowrie output (JSON logs or runtime events)
and normalizes them into the unified SecurityEvent schema.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any, Dict, Optional

from shared.event_schema import SecurityEvent, EventType, EventStatus, ProtocolType
from shared.config import settings


class CowrieSSHAdapter:
    """Normalizes Cowrie SSH events into standard SecurityEvent instances."""

    EVENT_MAP = {
        "cowrie.session.connect": (EventType.SESSION_CONNECT.value, EventStatus.ATTEMPT.value),
        "cowrie.login.failed": (EventType.LOGIN_FAILED.value, EventStatus.FAILED.value),
        "cowrie.login.success": (EventType.LOGIN_SUCCESS.value, EventStatus.SUCCESS.value),
        "cowrie.command.input": (EventType.COMMAND_EXECUTION.value, EventStatus.EXECUTED.value),
        "cowrie.command.failed": (EventType.COMMAND_EXECUTION.value, EventStatus.FAILED.value),
        "cowrie.session.file_download": (EventType.FILE_DOWNLOAD.value, EventStatus.SUCCESS.value),
        "cowrie.session.file_upload": (EventType.FILE_UPLOAD.value, EventStatus.SUCCESS.value),
        "cowrie.session.closed": (EventType.SESSION_DISCONNECT.value, EventStatus.CLOSED.value),
    }

    @staticmethod
    def _format_timestamp(raw_ts: Optional[str]) -> str:
        """Ensure timestamp is valid ISO 8601 UTC string ending in 'Z'."""
        if not raw_ts:
            return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            # Handle ISO string with fractional seconds or without Z
            cleaned = raw_ts.replace("Z", "+00:00")
            dt = datetime.fromisoformat(cleaned)
            return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    @classmethod
    def normalize(
        cls,
        raw: Dict[str, Any],
        asset_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> Optional[SecurityEvent]:
        """Normalize a raw Cowrie event dictionary into a SecurityEvent.

        Returns None if the event is unmapped or purely internal diagnostics.
        """
        raw_eventid = raw.get("eventid")
        if not raw_eventid or raw_eventid not in cls.EVENT_MAP:
            # Skip unmapped diagnostic events (e.g. client key exchange details)
            return None

        event_type, status = cls.EVENT_MAP[raw_eventid]
        src_ip = raw.get("src_ip", "127.0.0.1")
        src_port = raw.get("src_port")
        username = raw.get("username")
        timestamp = cls._format_timestamp(raw.get("timestamp"))

        # Build clean metadata without leaking plaintext passwords
        metadata: Dict[str, Any] = {
            "hostname": settings.SSH_HOSTNAME,
            "session_id": raw.get("session"),
            "system": raw.get("system", "cowrie.ssh"),
        }

        # Event-specific metadata
        if raw_eventid == "cowrie.login.failed":
            pwd = raw.get("password")
            metadata["password_length"] = len(pwd) if pwd is not None else 0
            # Mark if attempting known bait account
            if username == "finance_admin":
                metadata["bait_credential_targeted"] = True
                event_type = EventType.LOGIN_FAILED.value

        elif raw_eventid == "cowrie.login.success":
            if username == "finance_admin":
                metadata["bait_credential_triggered"] = True
                metadata["alert_priority"] = "HIGH"

        elif raw_eventid in ("cowrie.command.input", "cowrie.command.failed"):
            metadata["command"] = raw.get("input", "")

        elif raw_eventid == "cowrie.session.file_download":
            metadata["url"] = raw.get("url")
            metadata["outfile"] = raw.get("outfile")
            metadata["shasum"] = raw.get("shasum")

        elif raw_eventid == "cowrie.session.file_upload":
            metadata["filename"] = raw.get("filename")
            metadata["shasum"] = raw.get("shasum")

        elif raw_eventid == "cowrie.session.closed":
            metadata["duration_seconds"] = raw.get("duration")

        active_tenant = tenant_id or settings.DEFAULT_TENANT_ID
        metadata["tenant_id"] = active_tenant

        return SecurityEvent(
            asset_id=asset_id or settings.SSH_ASSET_ID,
            tenant_id=active_tenant,
            source_service="ssh",
            event_type=event_type,
            source_ip=src_ip,
            source_port=src_port,
            username=username,
            protocol=ProtocolType.SSH.value,
            timestamp=timestamp,
            status=status,
            metadata=metadata,
        )

    @classmethod
    def normalize_json_line(
        cls,
        line: str,
        asset_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> Optional[SecurityEvent]:
        """Parse a JSON string line and normalize it."""
        try:
            data = json.loads(line.strip())
            return cls.normalize(data, asset_id=asset_id, tenant_id=tenant_id)
        except Exception:
            return None

