"""Pydantic schemas for Attack Events and Ingestion."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, ConfigDict, Field, field_validator


class SeverityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackEventBase(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: Optional[str] = None
    source_ip: str
    source_port: Optional[int] = None
    source_service: str
    asset_id: str
    event_type: str
    username: Optional[str] = None
    severity: str = SeverityLevel.LOW.value
    status: str = "attempt"
    timestamp: datetime
    activity: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp(cls, v: Any) -> datetime:
        if isinstance(v, datetime):
            return v.astimezone(timezone.utc)
        if isinstance(v, str):
            cleaned = v.replace("Z", "+00:00")
            dt = datetime.fromisoformat(cleaned)
            return dt.astimezone(timezone.utc)
        raise ValueError(f"Invalid timestamp value: {v}")


class AttackEventCreate(AttackEventBase):
    pass


class MitreMappingItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    technique_id: str
    technique_name: str
    tactic: str
    confidence: float
    evidence: str


class AttackEventResponse(AttackEventBase):
    model_config = ConfigDict(from_attributes=True)

    created_at: Optional[datetime] = None
    mitre_techniques: List[MitreMappingItem] = Field(default_factory=list)


class PaginatedEventsResponse(BaseModel):
    total: int
    page: int
    page_size: int
    total_pages: int
    items: List[AttackEventResponse]


class IngestionResponse(BaseModel):
    status: str = "success"
    processed: int
    persisted: int
    duplicates_skipped: int
    errors: List[str] = Field(default_factory=list)
