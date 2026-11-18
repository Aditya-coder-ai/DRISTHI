"""SQLAlchemy model for Deployment Registration."""

from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Index
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import relationship
import sqlalchemy as sa

from backend.app.database.base import Base

JSONType = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


class Deployment(Base):
    """Tracks deployment lifecycle of deceptive assets registered with the central backend."""
    __tablename__ = "deployments"

    deployment_id = Column(String(64), primary_key=True, index=True)
    asset_id = Column(
        String(64),
        ForeignKey("deceptive_assets.asset_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    tenant_id = Column(
        String(64),
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    asset_type = Column(String(32), nullable=False, index=True)
    environment = Column(String(32), default="production", nullable=False)
    version = Column(String(64), nullable=True)
    hostname = Column(String(128), nullable=True)
    ip_address = Column(String(45), nullable=True)
    port = Column(Integer, nullable=True)
    status = Column(String(32), default="registered", nullable=False, index=True)
    registered_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    last_heartbeat_at = Column(DateTime(timezone=True), nullable=True)
    deploy_metadata = Column(JSONType, default=dict, nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    asset = relationship("DeceptiveAsset", backref="deployments")
    tenant = relationship("Tenant", backref="deployments")

    __table_args__ = (
        Index("ix_deployments_tenant_type", "tenant_id", "asset_type"),
        Index("ix_deployments_tenant_status", "tenant_id", "status"),
        Index("ix_deployments_asset_tenant", "asset_id", "tenant_id"),
    )

    def to_dict(self):
        return {
            "deployment_id": self.deployment_id,
            "asset_id": self.asset_id,
            "tenant_id": self.tenant_id,
            "asset_type": self.asset_type,
            "environment": self.environment,
            "version": self.version,
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "port": self.port,
            "status": self.status,
            "registered_at": self.registered_at.isoformat() if self.registered_at else None,
            "last_heartbeat_at": self.last_heartbeat_at.isoformat() if self.last_heartbeat_at else None,
            "deploy_metadata": self.deploy_metadata or {},
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
