"""SQLAlchemy model for Deceptive Assets."""

from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, ForeignKey, Index
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import relationship
import sqlalchemy as sa

from backend.app.database.base import Base

JSONType = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


class DeceptiveAsset(Base):
    """Represents a deployed deceptive honeypot, honeytoken, or decoy resource."""
    __tablename__ = "deceptive_assets"

    asset_id = Column(String(64), primary_key=True, index=True)
    tenant_id = Column(
        String(64),
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name = Column(String(128), nullable=False)
    asset_type = Column(String(32), nullable=False, index=True)
    description = Column(String(256), nullable=True)
    deployment_id = Column(String(64), nullable=True, index=True)
    environment = Column(String(32), default="production", nullable=False)
    status = Column(String(32), default="active", nullable=False, index=True)
    config_metadata = Column(JSONType, default=dict, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    tenant = relationship("Tenant", backref="deceptive_assets")

    __table_args__ = (
        Index("ix_assets_tenant_type", "tenant_id", "asset_type"),
        Index("ix_assets_tenant_status", "tenant_id", "status"),
    )

    def to_dict(self):
        return {
            "asset_id": self.asset_id,
            "tenant_id": self.tenant_id,
            "name": self.name,
            "asset_type": self.asset_type,
            "description": self.description,
            "deployment_id": self.deployment_id,
            "environment": self.environment,
            "status": self.status,
            "config_metadata": self.config_metadata or {},
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
