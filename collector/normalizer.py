"""Central Event Normalizer for all Deception Assets.

Accepts raw event payloads from any decoy service and produces standardized,
validated SecurityEvent instances.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from shared.event_schema import SecurityEvent, ProtocolType
from services.ssh.ssh_event_adapter import CowrieSSHAdapter
from services.ftp.ftp_event_adapter import FTPEventAdapter
from services.web.web_event_adapter import WebEventAdapter
from services.database.db_event_adapter import DatabaseEventAdapter


class EventNormalizer:
    """Dispatches raw events to protocol-specific adapters and validates output."""

    @classmethod
    def normalize(
        cls,
        raw_event: Dict[str, Any],
        protocol: str = ProtocolType.SSH.value,
        asset_id: Optional[str] = None,
    ) -> Optional[SecurityEvent]:
        """Normalize a raw event dictionary.

        Args:
            raw_event: Raw telemetry dictionary from the honeypot/decoy service.
            protocol: Protocol identifier (SSH, FTP, HTTP, DATABASE).
            asset_id: Optional asset identifier override.

        Returns:
            Validated SecurityEvent instance, or None if skipped/invalid.
        """
        protocol_upper = protocol.upper()

        if protocol_upper == ProtocolType.SSH.value:
            return CowrieSSHAdapter.normalize(raw_event, asset_id=asset_id)

        if protocol_upper == ProtocolType.FTP.value:
            return FTPEventAdapter.normalize(raw_event, asset_id=asset_id)

        if protocol_upper == ProtocolType.HTTP.value:
            return WebEventAdapter.normalize(raw_event, asset_id=asset_id)

        if protocol_upper in (ProtocolType.DATABASE.value, "POSTGRESQL", "MYSQL"):
            return DatabaseEventAdapter.normalize(raw_event, asset_id=asset_id)

        return None

