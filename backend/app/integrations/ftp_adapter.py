"""Specialized FTP Telemetry Adapter."""

from typing import Any, Dict, Optional
from backend.app.integrations.person1_adapter import Person1SecurityEventAdapter
from backend.app.schemas.event import AttackEventCreate


class FTPTelemetryAdapter(Person1SecurityEventAdapter):
    """Adapter specifically tuned for FTP Honeypot events."""

    def adapt(self, raw_data: Dict[str, Any]) -> Optional[AttackEventCreate]:
        raw_copy = dict(raw_data)
        if "protocol" not in raw_copy:
            raw_copy["protocol"] = "FTP"
        if "asset_id" not in raw_copy:
            raw_copy["asset_id"] = "ftp-001"
        return super().adapt(raw_copy)

