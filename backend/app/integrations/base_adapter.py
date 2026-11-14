"""Base Telemetry Ingestion Adapter interface."""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
from backend.app.schemas.event import AttackEventCreate


class BaseTelemetryAdapter(ABC):
    """Abstract base class for converting external honeypot telemetry into AttackEventCreate."""

    @abstractmethod
    def adapt(self, raw_data: Dict[str, Any]) -> Optional[AttackEventCreate]:
        pass

