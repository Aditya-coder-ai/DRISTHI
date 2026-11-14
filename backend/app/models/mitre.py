"""MITRE ATT&CK Mapping SQLAlchemy model."""

from datetime import datetime, timezone
from typing import Any, Dict
from sqlalchemy import Column, String, Integer, Float, Text, DateTime, ForeignKey, Index
from sqlalchemy.orm import relationship
from backend.app.database.base import Base


class MitreMapping(Base):
    __tablename__ = "mitre_mappings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(String(64), ForeignKey("attack_events.event_id", ondelete="CASCADE"), nullable=False, index=True)
    technique_id = Column(String(32), nullable=False, index=True)      # e.g., T1110.001
    technique_name = Column(String(128), nullable=False)              # e.g., Password Guessing
    tactic = Column(String(64), nullable=False, default="Initial Access")  # e.g., Credential Access
    confidence = Column(Float, nullable=False, default=1.0)           # 0.0 - 1.0
    evidence = Column(Text, nullable=False)                           # Evidence string
    mapping_source = Column(String(32), nullable=False, default="rule_engine")
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    # Relationship
    event = relationship("AttackEvent", back_populates="mitre_mappings")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "event_id": self.event_id,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "mapping_source": self.mapping_source,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

