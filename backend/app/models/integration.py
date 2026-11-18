"""SQLAlchemy model for Integration Configuration Registry."""

from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Index
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import relationship
import sqlalchemy as sa

from backend.app.database.base import Base

JSONType = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


class IntegrationConfig(Base):
    """Stores configuration for external SIEM, Webhook, and Security Monitoring integrations."""
    __tablename__ = "integration_configs"

    integration_id = Column(String(64), primary_key=True, index=True)
    tenant_id = Column(
        String(64),
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name = Column(String(128), nullable=False)
    integration_type = Column(String(32), nullable=False, index=True)
    enabled = Column(Boolean, default=True, nullable=False, index=True)
    status = Column(String(32), default="configured", nullable=False, index=True)
    config_metadata = Column(JSONType, default=dict, nullable=False)
    secret_masked = Column(String(128), nullable=True)
    secret_hash = Column(String(64), nullable=True)
    secret_storage = Column(String(256), nullable=True)
    last_validated_at = Column(DateTime(timezone=True), nullable=True)
    validation_details = Column(JSONType, default=dict, nullable=False)
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

    tenant = relationship("Tenant", backref="integrations")

    __table_args__ = (
        Index("ix_integrations_tenant_type", "tenant_id", "integration_type"),
        Index("ix_integrations_tenant_enabled", "tenant_id", "enabled"),
        Index("ix_integrations_tenant_status", "tenant_id", "status"),
    )

    def to_dict(self):
        """Returns safe representation with credentials masked."""
        return {
            "integration_id": self.integration_id,
            "tenant_id": self.tenant_id,
            "name": self.name,
            "integration_type": self.integration_type,
            "enabled": self.enabled,
            "status": self.status,
            "config_metadata": self.config_metadata or {},
            "has_secret": bool(self.secret_hash or self.secret_storage),
            "secret_masked": self.secret_masked,
            "last_validated_at": self.last_validated_at.isoformat() if self.last_validated_at else None,
            "validation_details": self.validation_details or {},
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
