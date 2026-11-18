"""Adapter for normalizing Person 1's SecurityEvent objects into AttackEventCreate."""

from datetime import datetime, timezone
from typing import Any, Dict, Optional
import uuid

from backend.app.core.security import sanitize_credentials
from backend.app.integrations.base_adapter import BaseTelemetryAdapter
from backend.app.schemas.event import AttackEventCreate, SeverityLevel


class Person1SecurityEventAdapter(BaseTelemetryAdapter):
    """Translates Person 1 SecurityEvent payloads into DRISTHI AttackEventCreate models."""

    SERVICE_MAP = {
        "SSH": "ssh",
        "FTP": "ftp",
        "HTTP": "web",
        "DATABASE": "database",
        "POSTGRESQL": "database",
        "MYSQL": "database",
    }

    CRITICAL_EVENT_TYPES = {
        "canary_triggered",
        "credential_reuse",
    }

    HIGH_EVENT_TYPES = {
        "bait_credential_trigger",
        "suspicious_request",
    }

    HIGH_COMMANDS = {
        "/etc/shadow",
        "/etc/passwd",
        "sudo",
        "curl",
        "wget",
        "nc",
        "ncat",
        "netcat",
        "chmod +x",
        "rm -rf",
        "whoami",
        "id",
        "uname",
    }

    @classmethod
    def calculate_severity(cls, raw: Dict[str, Any]) -> str:
        """Determines event severity based on objective interaction evidence."""
        event_type = str(raw.get("event_type", "")).lower()
        metadata = raw.get("metadata", {}) or {}

        # 1. Critical: Canary tripped or cross-service lateral credential reuse
        if event_type in cls.CRITICAL_EVENT_TYPES:
            return SeverityLevel.CRITICAL.value

        if metadata.get("canary_triggered") or metadata.get("credential_reuse"):
            return SeverityLevel.CRITICAL.value

        # 2. High: Bait credentials triggered, high-alert priority, or privileged command execution
        if event_type in cls.HIGH_EVENT_TYPES:
            return SeverityLevel.HIGH.value

        if metadata.get("alert_priority") == "HIGH" or metadata.get("bait_credential_triggered"):
            return SeverityLevel.HIGH.value

        command = str(metadata.get("command") or metadata.get("input") or "")
        if any(hc in command for hc in cls.HIGH_COMMANDS):
            return SeverityLevel.HIGH.value

        query = str(metadata.get("query") or "").lower()
        if any(sq in query for sq in ("executive_compensation", "payroll", "shadow", "drop table", "union select")):
            return SeverityLevel.HIGH.value

        # 3. Medium: Failed logins, directory listing, file access
        if event_type in ("login_failed", "login_attempt", "file_download", "file_upload", "database_enumeration"):
            return SeverityLevel.MEDIUM.value

        if metadata.get("bait_credential_targeted"):
            return SeverityLevel.MEDIUM.value

        # 4. Low: Default baseline telemetry
        return SeverityLevel.LOW.value

    @classmethod
    def extract_activity(cls, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Extracts structured activity details from metadata without leaking plaintext credentials."""
        metadata = raw.get("metadata", {}) or {}
        activity = {}

        if "command" in metadata:
            activity["command"] = metadata["command"]
        elif "input" in metadata:
            activity["command"] = metadata["input"]

        if "query" in metadata:
            activity["query"] = metadata["query"]
            activity["database"] = metadata.get("database")

        if "path" in metadata:
            activity["path"] = metadata["path"]
            activity["action"] = metadata.get("action", "file_access")
            activity["filename"] = metadata.get("filename")
            activity["bytes_transferred"] = metadata.get("bytes_transferred")

        if "url" in metadata:
            activity["url"] = metadata["url"]

        if "reason" in metadata:
            activity["reason"] = metadata["reason"]

        if "username" in raw and raw["username"]:
            activity["username"] = raw["username"]

        activity["action_type"] = raw.get("event_type")
        return activity

    def adapt(self, raw_data: Dict[str, Any]) -> Optional[AttackEventCreate]:
        """Normalizes dictionary payload into AttackEventCreate."""
        if not isinstance(raw_data, dict):
            return None

        # Sanitize any raw password keys
        clean_raw = sanitize_credentials(raw_data)
        metadata = clean_raw.get("metadata", {}) or {}
        clean_metadata = sanitize_credentials(metadata)

        # Preserve honeytoken identification in metadata
        if "honeytoken_id" in clean_raw and "honeytoken_id" not in clean_metadata:
            clean_metadata["honeytoken_id"] = clean_raw["honeytoken_id"]
        if "trigger_type" in clean_raw and "trigger_type" not in clean_metadata:
            clean_metadata["trigger_type"] = clean_raw["trigger_type"]

        # Event ID
        event_id = clean_raw.get("event_id") or str(uuid.uuid4())

        # Protocol & Service determination
        raw_proto = str(clean_raw.get("protocol", "")).upper()
        asset_id = clean_raw.get("asset_id") or clean_raw.get("source_service") or "unknown-service"

        if raw_proto in self.SERVICE_MAP:
            source_service = self.SERVICE_MAP[raw_proto]
        elif "-" in asset_id:
            source_service = asset_id.split("-")[0].lower()
        else:
            source_service = clean_raw.get("source_service", "generic").lower()

        # Session ID extraction
        session_id = clean_raw.get("session_id") or clean_metadata.get("session_id") or clean_metadata.get("session")

        # Severity calculation
        severity = clean_raw.get("severity") or self.calculate_severity(clean_raw)

        # Activity extraction
        activity = clean_raw.get("activity") or self.extract_activity(clean_raw)

        # Source IP and Port
        source_ip = clean_raw.get("source_ip", "127.0.0.1")
        source_port = clean_raw.get("source_port")

        # Timestamp normalization
        raw_ts = clean_raw.get("timestamp")
        if not raw_ts:
            ts = datetime.now(timezone.utc)
        elif isinstance(raw_ts, datetime):
            ts = raw_ts.astimezone(timezone.utc)
        elif isinstance(raw_ts, str):
            try:
                cleaned_ts = raw_ts.replace("Z", "+00:00")
                ts = datetime.fromisoformat(cleaned_ts).astimezone(timezone.utc)
            except Exception:
                ts = datetime.now(timezone.utc)
        else:
            ts = datetime.now(timezone.utc)

        # Tenant ID extraction
        tenant_id = clean_raw.get("tenant_id") or clean_metadata.get("tenant_id") or "tenant-apex-001"

        return AttackEventCreate(
            event_id=str(event_id),
            tenant_id=str(tenant_id),
            session_id=str(session_id) if session_id else None,
            source_ip=str(source_ip),
            source_port=int(source_port) if source_port is not None else None,
            source_service=str(source_service),
            asset_id=str(asset_id),
            event_type=str(clean_raw.get("event_type", "unknown")),
            username=str(clean_raw.get("username")) if clean_raw.get("username") else None,
            severity=str(severity),
            status=str(clean_raw.get("status", "attempt")),
            timestamp=ts,
            activity=activity,
            metadata=clean_metadata,
        )

