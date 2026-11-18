"""SQLAlchemy model for Honeytokens."""

from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Index
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import relationship
import sqlalchemy as sa

from backend.app.database.base import Base

JSONType = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


class Honeytoken(Base):
    """Represents a decoy credential, API key, AWS token, or canary asset."""
    __tablename__ = "honeytokens"

    token_id = Column(String(64), primary_key=True, index=True)
    tenant_id = Column(
        String(64),
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    asset_id = Column(
        String(64),
        ForeignKey("deceptive_assets.asset_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    token_type = Column(String(32), nullable=False, index=True)
    name = Column(String(128), nullable=False)
    description = Column(String(256), nullable=True)
    token_value_masked = Column(String(128), nullable=False)
    token_hash = Column(String(64), nullable=False, index=True)
    status = Column(String(32), default="active", nullable=False, index=True)
    token_metadata = Column("metadata", JSONType, default=dict, nullable=False)
    trigger_count = Column(Integer, default=0, nullable=False)
    last_triggered_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    tenant = relationship("Tenant", backref="honeytokens")
    asset = relationship("DeceptiveAsset", backref="honeytokens")

    __table_args__ = (
        Index("ix_honeytokens_tenant_status", "tenant_id", "status"),
        Index("ix_honeytokens_tenant_asset", "tenant_id", "asset_id"),
        Index("ix_honeytokens_tenant_type", "tenant_id", "token_type"),
    )

    def to_dict(self):
        return {
            "token_id": self.token_id,
            "tenant_id": self.tenant_id,
            "asset_id": self.asset_id,
            "token_type": self.token_type,
            "name": self.name,
            "description": self.description,
            "token_value_masked": self.token_value_masked,
            "token_hash": self.token_hash,
            "status": self.status,
            "metadata": self.token_metadata or {},
            "trigger_count": self.trigger_count,
            "last_triggered_at": self.last_triggered_at.isoformat() if self.last_triggered_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
