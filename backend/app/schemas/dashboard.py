"""Pydantic schemas for Dashboard Analytics."""

from typing import Dict, List
from pydantic import BaseModel, Field


class ServiceCountItem(BaseModel):
    service: str
    count: int


class UsernameCountItem(BaseModel):
    username: str
    count: int


class CommandCountItem(BaseModel):
    command: str
    count: int


class DashboardStatsResponse(BaseModel):
    total_events: int
    unique_attackers: int
    active_sessions: int
    canary_triggers: int
    severity_breakdown: Dict[str, int] = Field(default_factory=dict)
    top_targeted_services: List[ServiceCountItem] = Field(default_factory=list)
    top_usernames: List[UsernameCountItem] = Field(default_factory=list)
    top_commands: List[CommandCountItem] = Field(default_factory=list)


class TimelineBucket(BaseModel):
    time_bucket: str
    event_count: int
    critical_count: int = 0
    high_count: int = 0


class TimelineResponse(BaseModel):
    interval: str
    buckets: List[TimelineBucket] = Field(default_factory=list)


class ServiceActivityDetail(BaseModel):
    service: str
    asset_id: str
    total_events: int
    unique_attackers: int
    active_sessions: int
    last_event_time: str


class ServiceActivityResponse(BaseModel):
    services: List[ServiceActivityDetail] = Field(default_factory=list)

