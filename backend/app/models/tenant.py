"""Tenant SQLAlchemy Model for Multi-Tenant Isolation."""

from datetime import datetime, timezone
from typing import Any, Dict
from sqlalchemy import Column, String, Boolean, DateTime
from backend.app.database.base import Base


class Tenant(Base):
    __tablename__ = "tenants"

    tenant_id = Column(String(64), primary_key=True, index=True)
    name = Column(String(128), nullable=False)
    description = Column(String(256), nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "name": self.name,
            "description": self.description,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
