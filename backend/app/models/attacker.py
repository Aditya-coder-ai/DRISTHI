"""Attacker Profile SQLAlchemy model."""

from datetime import datetime, timezone
from typing import Any, Dict, List
from sqlalchemy import Column, String, Integer, Float, DateTime, Index, JSON
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import relationship
from backend.app.database.base import Base

JSONType = JSON().with_variant(postgresql.JSONB(), "postgresql")


class AttackerProfile(Base):
    __tablename__ = "attacker_profiles"

    attacker_id = Column(String(64), primary_key=True, index=True)
    source_ip = Column(String(64), unique=True, nullable=False, index=True)
    first_seen = Column(DateTime(timezone=True), nullable=False)
    last_seen = Column(DateTime(timezone=True), nullable=False, index=True)
    total_events = Column(Integer, nullable=False, default=0)
    total_sessions = Column(Integer, nullable=False, default=0)
    highest_severity = Column(String(16), nullable=False, default="low")  # low, medium, high, critical
    attempted_usernames = Column(JSONType, nullable=False, default=list)  # ["admin", "root"]
    attempted_commands = Column(JSONType, nullable=False, default=list)   # ["uname -a", "cat /etc/passwd"]
    services_targeted = Column(JSONType, nullable=False, default=list)    # ["ssh", "ftp"]
    risk_score = Column(Float, nullable=False, default=0.0)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    sessions = relationship("AttackerSession", back_populates="attacker")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attacker_id": self.attacker_id,
            "source_ip": self.source_ip,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "total_events": self.total_events,
            "total_sessions": self.total_sessions,
            "highest_severity": self.highest_severity,
            "attempted_usernames": self.attempted_usernames or [],
            "attempted_commands": self.attempted_commands or [],
            "services_targeted": self.services_targeted or [],
            "risk_score": self.risk_score,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

