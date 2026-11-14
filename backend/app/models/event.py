"""Attack Event SQLAlchemy model."""

from datetime import datetime, timezone
from typing import Any, Dict, List
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Index, JSON
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import relationship
from backend.app.database.base import Base

# Dialect-adaptive JSON type (JSONB on PostgreSQL, JSON on SQLite)
JSONType = JSON().with_variant(postgresql.JSONB(), "postgresql")


class AttackEvent(Base):
    __tablename__ = "attack_events"

    event_id = Column(String(64), primary_key=True, index=True)
    session_id = Column(String(64), ForeignKey("attacker_sessions.session_id", ondelete="SET NULL"), nullable=True, index=True)
    source_ip = Column(String(64), nullable=False, index=True)
    source_port = Column(Integer, nullable=True)
    source_service = Column(String(32), nullable=False, index=True)  # ssh, ftp, web, database
    asset_id = Column(String(64), nullable=False, index=True)        # ssh-001, ftp-001, etc.
    event_type = Column(String(64), nullable=False, index=True)      # login_attempt, command_execution, etc.
    username = Column(String(128), nullable=True, index=True)
    severity = Column(String(16), nullable=False, default="low", index=True)  # low, medium, high, critical
    status = Column(String(32), nullable=False, default="attempt")   # success, failed, executed, detected, closed
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    activity = Column(JSONType, nullable=False, default=dict)        # Detailed captured action
    metadata_ = Column("metadata", JSONType, nullable=False, default=dict)  # Service contextual metadata
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    # Relationships
    session = relationship("AttackerSession", back_populates="events")
    mitre_mappings = relationship("MitreMapping", back_populates="event", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_events_service_severity_time", "source_service", "severity", "timestamp"),
        Index("ix_events_source_ip_timestamp", "source_ip", "timestamp"),
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "session_id": self.session_id,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "source_service": self.source_service,
            "asset_id": self.asset_id,
            "event_type": self.event_type,
            "username": self.username,
            "severity": self.severity,
            "status": self.status,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "activity": self.activity or {},
            "metadata": self.metadata_ or {},
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "mitre_techniques": [m.to_dict() for m in self.mitre_mappings] if self.mitre_mappings else [],
        }

