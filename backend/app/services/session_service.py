"""Attacker Session Lifecycle Management Service."""

from datetime import datetime, timezone, timedelta
from typing import Optional
import uuid
from sqlalchemy.orm import Session
from backend.app.core.config import settings
from backend.app.models.session import AttackerSession
from backend.app.schemas.event import AttackEventCreate, SeverityLevel
from backend.app.utils.timestamps import ensure_utc


class SessionService:
    """Manages creation, association, updates, and timeouts for attacker sessions."""

    def __init__(self, db: Session):
        self.db = db

    def get_or_create_session(self, event: AttackEventCreate, attacker_id: Optional[str] = None) -> AttackerSession:
        """Finds an existing active session or initializes a new one based on event telemetry."""
        now = ensure_utc(event.timestamp)
        timeout_threshold = now - timedelta(seconds=settings.SESSION_IDLE_TIMEOUT_SECONDS)

        session: Optional[AttackerSession] = None

        # 1. Check if event specifically supplies an existing session ID
        if event.session_id:
            session = self.db.query(AttackerSession).filter(
                AttackerSession.session_id == event.session_id
            ).first()

        # 2. Heuristic grouping: Look for active session matching source_ip within idle threshold
        if not session:
            candidates = self.db.query(AttackerSession).filter(
                AttackerSession.source_ip == event.source_ip,
                AttackerSession.status.in_(["active", "escalated"]),
            ).order_by(AttackerSession.last_seen.desc()).all()

            for cand in candidates:
                cand_last_seen = ensure_utc(cand.last_seen)
                if cand_last_seen >= timeout_threshold:
                    session = cand
                    break

        # 3. Update existing session
        if session:
            sess_last_seen = ensure_utc(session.last_seen)
            if now > sess_last_seen:
                session.last_seen = now
            session.event_count += 1

            # Append service if new
            services = list(session.services_accessed or [])
            if event.source_service not in services:
                services.append(event.source_service)
                session.services_accessed = services

            # Link attacker_id if newly resolved
            if attacker_id and not session.attacker_id:
                session.attacker_id = attacker_id

            # Escalate status if critical severity
            if event.severity == SeverityLevel.CRITICAL.value:
                session.status = "escalated"
            elif event.event_type in ("session_disconnect", "session_closed"):
                session.status = "closed"

            return session

        # 4. Create new session
        new_session_id = event.session_id or f"sess-{uuid.uuid4().hex[:12]}"
        services = [event.source_service] if event.source_service else []
        initial_status = "escalated" if event.severity == SeverityLevel.CRITICAL.value else "active"
        if event.event_type in ("session_disconnect", "session_closed"):
            initial_status = "closed"

        session = AttackerSession(
            session_id=new_session_id,
            attacker_id=attacker_id,
            source_ip=event.source_ip,
            first_seen=now,
            last_seen=now,
            services_accessed=services,
            event_count=1,
            status=initial_status,
        )
        self.db.add(session)
        self.db.flush()
        return session

