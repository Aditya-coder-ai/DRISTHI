"""Pydantic schemas for Attacker Profiles."""

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field


class AttackerProfileResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    attacker_id: str
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
