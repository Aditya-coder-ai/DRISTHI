"""Pydantic schemas for System Health."""

from datetime import datetime
from pydantic import BaseModel


class HealthResponse(BaseModel):
    status: str = "healthy"
    version: str
    database: str
    active_sessions: int
    total_events: int
    timestamp: datetime

