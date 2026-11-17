"""Database Deception Event Adapter.

Normalizes raw PostgreSQL and MySQL telemetry into unified SecurityEvent instances (asset_id: db-001).
Redacts cleartext passwords and identifies bait credential usage.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from shared.config import settings
from shared.event_schema import EventStatus, EventType, ProtocolType, SecurityEvent


class DatabaseEventAdapter:
    """Normalizes database honeypot interactions into standard SecurityEvent records."""

    EVENT_MAP = {
        "db.session.connect": (EventType.SESSION_CONNECT.value, EventStatus.SUCCESS.value),
        "db.login.success": (EventType.LOGIN_SUCCESS.value, EventStatus.SUCCESS.value),
        "db.login.failed": (EventType.LOGIN_FAILED.value, EventStatus.FAILED.value),
        "db.query.execution": (EventType.QUERY_EXECUTION.value, EventStatus.EXECUTED.value),
        "db.query.enumeration": (EventType.DATABASE_ENUMERATION.value, EventStatus.DETECTED.value),
        "db.session.disconnect": (EventType.SESSION_DISCONNECT.value, EventStatus.CLOSED.value),
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
    def normalize(
        cls,
        raw: Dict[str, Any],
        asset_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> Optional[SecurityEvent]:
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
            "sub_protocol": raw.get("sub_protocol", "RDBMS"),
            "database": raw.get("database", "corporate_finance"),
            "session_id": raw.get("session_id"),
            "server_node": settings.DB_SERVER_NAME,
        }

        # Specific mappings
        if raw_eventid == "db.login.failed":
            pwd = raw.get("password")
            metadata["password_length"] = len(pwd) if pwd is not None else raw.get("password_length", 0)
            metadata["reason"] = "Authentication failed against simulated credentials"

        elif raw_eventid == "db.login.success":
            metadata["authenticated_user"] = username
            if username in ("database_root", "finance_admin", "backup_user", "admin"):
                metadata["bait_credential_triggered"] = True
                metadata["alert_priority"] = "HIGH"

        elif raw_eventid in ("db.query.execution", "db.query.enumeration"):
            metadata["query"] = raw.get("query", "")
            if raw_eventid == "db.query.enumeration":
                metadata["alert_priority"] = "MEDIUM"
                metadata["attack_vector"] = "Database Schema Discovery / Enumeration"

        elif raw_eventid == "db.session.disconnect":
            metadata["duration_seconds"] = raw.get("duration_seconds", 0)

        active_tenant = tenant_id or settings.DEFAULT_TENANT_ID
        metadata["tenant_id"] = active_tenant

        return SecurityEvent(
            asset_id=asset_id or settings.DB_ASSET_ID,
            tenant_id=active_tenant,
            source_service="database",
            event_type=event_type,
            source_ip=src_ip,
            source_port=src_port,
            username=username,
            protocol=ProtocolType.DATABASE.value,
            timestamp=timestamp,
            status=status,
            metadata=metadata,
        )

