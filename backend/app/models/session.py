"""Attacker Session SQLAlchemy model."""

from datetime import datetime, timezone
from typing import Any, Dict, List
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Index, JSON
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import relationship
from backend.app.database.base import Base

JSONType = JSON().with_variant(postgresql.JSONB(), "postgresql")


class AttackerSession(Base):
    __tablename__ = "attacker_sessions"

    session_id = Column(String(64), primary_key=True, index=True)
    attacker_id = Column(String(64), ForeignKey("attacker_profiles.attacker_id", ondelete="SET NULL"), nullable=True, index=True)
    source_ip = Column(String(64), nullable=False, index=True)
    first_seen = Column(DateTime(timezone=True), nullable=False)
    last_seen = Column(DateTime(timezone=True), nullable=False, index=True)
    services_accessed = Column(JSONType, nullable=False, default=list)  # ["ssh", "ftp"]
    event_count = Column(Integer, nullable=False, default=1)
    status = Column(String(16), nullable=False, default="active", index=True)  # active, idle, closed, escalated
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    attacker = relationship("AttackerProfile", back_populates="sessions")
    events = relationship("AttackEvent", back_populates="session")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "attacker_id": self.attacker_id,
            "source_ip": self.source_ip,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "services_accessed": self.services_accessed or [],
            "event_count": self.event_count,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

