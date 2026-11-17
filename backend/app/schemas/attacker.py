"""Pydantic schemas for Attacker Profiles."""

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field, model_validator


class AttackerProfileResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    attacker_id: str
    tenant_id: str = "tenant-apex-001"
    source_ip: str
    first_seen: datetime
    last_seen: datetime
    total_events: int
    total_sessions: int
    highest_severity: str
    attempted_usernames: List[str] = Field(default_factory=list)
    attempted_commands: List[str] = Field(default_factory=list)
    services_targeted: List[str] = Field(default_factory=list)
    risk_score: float
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class PaginatedAttackersResponse(BaseModel):
    total: int
    page: int
    page_size: int
    total_pages: int
    items: List[AttackerProfileResponse]
    limit: Optional[int] = None

    @model_validator(mode="after")
    def sync_limit(self) -> "PaginatedAttackersResponse":
        if self.limit is None:
            self.limit = self.page_size
        return self
