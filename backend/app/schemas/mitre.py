"""Pydantic schemas for MITRE ATT&CK Mappings."""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict


class MitreMappingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    event_id: str
    technique_id: str
    technique_name: str
    tactic: str
    confidence: float
    evidence: str
    mapping_source: str
    created_at: Optional[datetime] = None
