"""Pydantic schemas for Tenant Management."""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field


class TenantBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    description: Optional[str] = Field(None, max_length=256)


class TenantCreate(TenantBase):
    tenant_id: str = Field(..., min_length=3, max_length=64)


class TenantResponse(TenantBase):
    model_config = ConfigDict(from_attributes=True)

    tenant_id: str
    is_active: bool = True
    created_at: Optional[datetime] = None
