"""SQLAlchemy model for Webhook Delivery tracking."""

from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Index
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import relationship
import sqlalchemy as sa

from backend.app.database.base import Base

JSONType = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


class WebhookDelivery(Base):
    """Tracks individual webhook notification attempts, responses, and retry states."""
    __tablename__ = "webhook_deliveries"

    delivery_id = Column(String(64), primary_key=True, index=True)
    tenant_id = Column(
        String(64),
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    integration_id = Column(
        String(64),
        ForeignKey("integration_configs.integration_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    event_id = Column(
        String(64),
        ForeignKey("attack_events.event_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    destination_url = Column(String(512), nullable=False)
    event_type = Column(String(64), nullable=False, index=True)
    severity = Column(String(32), nullable=False)
    payload = Column(JSONType, default=dict, nullable=False)
    status = Column(String(32), default="pending", nullable=False, index=True)
    status_code = Column(Integer, nullable=True)
    response_body = Column(String(1024), nullable=True)
    attempts = Column(Integer, default=1, nullable=False)
    max_attempts = Column(Integer, default=3, nullable=False)
    last_attempt_at = Column(DateTime(timezone=True), nullable=True)
    next_retry_at = Column(DateTime(timezone=True), nullable=True)
    delivered_at = Column(DateTime(timezone=True), nullable=True)
    error_message = Column(String(512), nullable=True)
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

    tenant = relationship("Tenant", backref="webhook_deliveries")
    integration = relationship("IntegrationConfig", backref="deliveries")
    event = relationship("AttackEvent", backref="webhook_deliveries")

    __table_args__ = (
        Index("ix_deliveries_tenant_status", "tenant_id", "status"),
        Index("ix_deliveries_tenant_integration", "tenant_id", "integration_id"),
        Index("ix_deliveries_event_integration", "event_id", "integration_id"),
    )

    def to_dict(self):
        return {
            "delivery_id": self.delivery_id,
            "tenant_id": self.tenant_id,
            "integration_id": self.integration_id,
            "event_id": self.event_id,
            "destination_url": self.destination_url,
            "event_type": self.event_type,
            "severity": self.severity,
            "payload": self.payload or {},
            "status": self.status,
            "status_code": self.status_code,
            "response_body": self.response_body,
            "attempts": self.attempts,
            "max_attempts": self.max_attempts,
            "last_attempt_at": self.last_attempt_at.isoformat() if self.last_attempt_at else None,
            "next_retry_at": self.next_retry_at.isoformat() if self.next_retry_at else None,
            "delivered_at": self.delivered_at.isoformat() if self.delivered_at else None,
            "error_message": self.error_message,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
