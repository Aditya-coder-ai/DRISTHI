"""Specialized SSH Telemetry Adapter."""

from typing import Any, Dict, Optional
from backend.app.integrations.person1_adapter import Person1SecurityEventAdapter
from backend.app.schemas.event import AttackEventCreate


class SSHTelemetryAdapter(Person1SecurityEventAdapter):
    """Adapter specifically tuned for SSH Honeypot (Cowrie) events."""

    def adapt(self, raw_data: Dict[str, Any]) -> Optional[AttackEventCreate]:
        raw_copy = dict(raw_data)
        if "protocol" not in raw_copy:
            raw_copy["protocol"] = "SSH"
        if "asset_id" not in raw_copy:
            raw_copy["asset_id"] = "ssh-001"
        return super().adapt(raw_copy)

