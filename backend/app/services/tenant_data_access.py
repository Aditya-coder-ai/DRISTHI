"""Tenant-Scoped Data Access Layer.

Enforces strict tenant isolation at the data-access layer for:
- Attack Events
- Attacker Sessions
- Attacker Profiles

Guarantees:
- Every query is filtered by tenant_id.
- Direct lookups against foreign tenant records raise CrossTenantAccessDeniedException.
- No data leak across tenant boundaries.
"""

from datetime import datetime
from math import ceil
from typing import List, Optional, Tuple
from sqlalchemy import desc, asc
from sqlalchemy.orm import Session

from backend.app.core.exceptions import CrossTenantAccessDeniedException
from backend.app.models.attacker import AttackerProfile
from backend.app.models.event import AttackEvent
from backend.app.models.session import AttackerSession


class TenantDataAccess:
    """Data-access enforcement boundary scoped strictly to a specific tenant."""

    def __init__(self, db: Session, tenant_id: str):
        self.db = db
        self.tenant_id = tenant_id.strip()

    # --------------------------------------------------------------------------
    # Event Operations
    # --------------------------------------------------------------------------

    def get_event(self, event_id: str) -> Optional[AttackEvent]:
        """Fetch an event by ID, rejecting cross-tenant attempts."""
        event = self.db.query(AttackEvent).filter(AttackEvent.event_id == event_id).first()
        if not event:
            return None
        if event.tenant_id != self.tenant_id:
            raise CrossTenantAccessDeniedException(
                f"Access denied: event '{event_id}' belongs to tenant '{event.tenant_id}', not '{self.tenant_id}'"
            )
        return event

    def list_events(
        self,
        page: int = 1,
        page_size: int = 50,
        service: Optional[str] = None,
        severity: Optional[str] = None,
        event_type: Optional[str] = None,
        source_ip: Optional[str] = None,
        username: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        order_by: str = "timestamp_desc",
    ) -> Tuple[List[AttackEvent], int]:
        """Query events strictly constrained to self.tenant_id."""
        query = self.db.query(AttackEvent).filter(AttackEvent.tenant_id == self.tenant_id)

        if service:
            query = query.filter(AttackEvent.source_service == service.lower())
        if severity:
            query = query.filter(AttackEvent.severity == severity.lower())
        if event_type:
            query = query.filter(AttackEvent.event_type == event_type.lower())
        if source_ip:
            query = query.filter(AttackEvent.source_ip == source_ip.strip())
        if username:
            query = query.filter(AttackEvent.username == username.strip())
        if start_time:
            query = query.filter(AttackEvent.timestamp >= start_time)
        if end_time:
            query = query.filter(AttackEvent.timestamp <= end_time)

        if order_by == "timestamp_asc":
            query = query.order_by(asc(AttackEvent.timestamp))
        elif order_by == "severity_desc":
            query = query.order_by(desc(AttackEvent.severity), desc(AttackEvent.timestamp))
        else:
            query = query.order_by(desc(AttackEvent.timestamp))

        total = query.count()
        offset = (page - 1) * page_size
        items = query.offset(offset).limit(page_size).all()
        return items, total

    # --------------------------------------------------------------------------
    # Session Operations
    # --------------------------------------------------------------------------

    def get_session(self, session_id: str) -> Optional[AttackerSession]:
        """Fetch session by ID, rejecting cross-tenant attempts."""
        session = self.db.query(AttackerSession).filter(AttackerSession.session_id == session_id).first()
        if not session:
            return None
        if session.tenant_id != self.tenant_id:
            raise CrossTenantAccessDeniedException(
                f"Access denied: session '{session_id}' belongs to tenant '{session.tenant_id}', not '{self.tenant_id}'"
            )
        return session

    def list_sessions(
        self,
        page: int = 1,
        page_size: int = 20,
        status_filter: Optional[str] = None,
        source_ip: Optional[str] = None,
    ) -> Tuple[List[AttackerSession], int]:
        """Query sessions strictly constrained to self.tenant_id."""
        query = self.db.query(AttackerSession).filter(AttackerSession.tenant_id == self.tenant_id)

        if status_filter:
            query = query.filter(AttackerSession.status == status_filter.lower())
        if source_ip:
            query = query.filter(AttackerSession.source_ip == source_ip.strip())

        query = query.order_by(desc(AttackerSession.last_seen))
        total = query.count()
        offset = (page - 1) * page_size
        items = query.offset(offset).limit(page_size).all()
        return items, total

    # --------------------------------------------------------------------------
    # Attacker Profile Operations
    # --------------------------------------------------------------------------

    def get_attacker(self, identifier: str) -> Optional[AttackerProfile]:
        """Fetch attacker profile by ID or source IP, rejecting cross-tenant attempts."""
        profile = self.db.query(AttackerProfile).filter(
            (AttackerProfile.attacker_id == identifier) | (AttackerProfile.source_ip == identifier)
        ).first()

        if not profile:
            return None
        if profile.tenant_id != self.tenant_id:
            raise CrossTenantAccessDeniedException(
                f"Access denied: attacker '{identifier}' belongs to tenant '{profile.tenant_id}', not '{self.tenant_id}'"
            )
        return profile

    def list_attackers(
        self,
        page: int = 1,
        page_size: int = 20,
        min_severity: Optional[str] = None,
        search: Optional[str] = None,
    ) -> Tuple[List[AttackerProfile], int]:
        """Query attacker profiles strictly constrained to self.tenant_id."""
        query = self.db.query(AttackerProfile).filter(AttackerProfile.tenant_id == self.tenant_id)

        if search:
            query = query.filter(AttackerProfile.source_ip.contains(search.strip()))
        if min_severity:
            sev_order = ["low", "medium", "high", "critical"]
            if min_severity.lower() in sev_order:
                target_idx = sev_order.index(min_severity.lower())
                allowed = sev_order[target_idx:]
                query = query.filter(AttackerProfile.highest_severity.in_(allowed))

        query = query.order_by(desc(AttackerProfile.last_seen))
        total = query.count()
        offset = (page - 1) * page_size
        items = query.offset(offset).limit(page_size).all()
        return items, total
