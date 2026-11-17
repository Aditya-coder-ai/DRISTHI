"""FTP Deception Event Adapter.

Normalizes raw FTP activity telemetry into standard SecurityEvent instances.
Applies sensitive data redaction and flags bait credential triggers.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any, Dict, Optional

from shared.event_schema import SecurityEvent, EventType, EventStatus, ProtocolType
from shared.config import settings


class FTPEventAdapter:
    """Normalizes raw FTP interaction dictionaries into SecurityEvent instances."""

    EVENT_MAP = {
        "ftp.session.connect": (EventType.SESSION_CONNECT.value, EventStatus.ATTEMPT.value),
        "ftp.login.failed": (EventType.LOGIN_FAILED.value, EventStatus.FAILED.value),
        "ftp.login.success": (EventType.LOGIN_SUCCESS.value, EventStatus.SUCCESS.value),
        "ftp.directory.list": (EventType.FILE_ACCESS.value, EventStatus.EXECUTED.value),
        "ftp.file.download": (EventType.FILE_DOWNLOAD.value, EventStatus.SUCCESS.value),
        "ftp.file.upload": (EventType.FILE_UPLOAD.value, EventStatus.SUCCESS.value),
        "ftp.suspicious.request": (EventType.SUSPICIOUS_REQUEST.value, EventStatus.DETECTED.value),
        "ftp.session.closed": (EventType.SESSION_DISCONNECT.value, EventStatus.CLOSED.value),
    }

    @staticmethod
    def _format_timestamp(raw_ts: Optional[str]) -> str:
        """Format timestamp into ISO 8601 UTC string."""
        if not raw_ts:
            return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
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
        """Normalize a raw FTP telemetry event dictionary into a SecurityEvent."""
        raw_eventid = raw.get("eventid")
        if not raw_eventid or raw_eventid not in cls.EVENT_MAP:
            return None

        event_type, status = cls.EVENT_MAP[raw_eventid]
        src_ip = raw.get("src_ip", "127.0.0.1")
        src_port = raw.get("src_port")
        username = raw.get("username")
        timestamp = cls._format_timestamp(raw.get("timestamp"))

        # Baseline metadata
        metadata: Dict[str, Any] = {
            "server_name": raw.get("server_name", "Corp-Storage-Node-02"),
            "session_id": raw.get("session_id"),
            "system": "ftp.honeypot",
        }

        # Event-specific metadata
        if raw_eventid == "ftp.login.failed":
            pwd = raw.get("password")
            metadata["password_length"] = len(pwd) if pwd is not None else raw.get("password_length", 0)
            if username == "backup_user":
                metadata["bait_credential_targeted"] = True

        elif raw_eventid == "ftp.login.success":
            if username == "backup_user":
                metadata["bait_credential_triggered"] = True
                metadata["alert_priority"] = "HIGH"

        elif raw_eventid == "ftp.directory.list":
            metadata["action"] = "directory_listing"
            metadata["path"] = raw.get("path", "/")

        elif raw_eventid == "ftp.file.download":
            metadata["action"] = "file_download"
            metadata["path"] = raw.get("path")
            metadata["filename"] = raw.get("filename")
            metadata["bytes_transferred"] = raw.get("bytes_transferred", 0)

        elif raw_eventid == "ftp.file.upload":
            metadata["action"] = "file_upload"
            metadata["path"] = raw.get("path")
            metadata["filename"] = raw.get("filename")
            metadata["bytes_transferred"] = raw.get("bytes_transferred", 0)
            metadata["sha256"] = raw.get("sha256")

        elif raw_eventid == "ftp.suspicious.request":
            metadata["command"] = raw.get("command")
            metadata["argument"] = raw.get("argument")
            metadata["reason"] = raw.get("reason", "Unauthorized operation or path traversal attempt")
            metadata["alert_priority"] = "MEDIUM"

        elif raw_eventid == "ftp.session.closed":
            metadata["duration_seconds"] = raw.get("duration_seconds")
            metadata["commands_processed"] = raw.get("commands_processed", 0)

        active_tenant = tenant_id or settings.DEFAULT_TENANT_ID
        metadata["tenant_id"] = active_tenant

        return SecurityEvent(
            asset_id=asset_id or settings.FTP_ASSET_ID,
            tenant_id=active_tenant,
            source_service="ftp",
            event_type=event_type,
            source_ip=src_ip,
            source_port=src_port,
            username=username,
            protocol=ProtocolType.FTP.value,
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
        try:
            data = json.loads(line.strip())
            return cls.normalize(data, asset_id=asset_id, tenant_id=tenant_id)
        except Exception:
            return None

