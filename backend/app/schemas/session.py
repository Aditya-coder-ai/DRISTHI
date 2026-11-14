"""Pydantic schemas for Attacker Sessions."""

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field


class AttackerSessionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    session_id: str
    attacker_id: Optional[str] = None
    source_ip: str
    first_seen: datetime
    last_seen: datetime
    services_accessed: List[str] = Field(default_factory=list)
    event_count: int
    status: str
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class PaginatedSessionsResponse(BaseModel):
    total: int
    page: int
    page_size: int
    total_pages: int
    items: List[AttackerSessionResponse]
