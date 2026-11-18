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

from datetime import datetime, timezone
from math import ceil
from typing import List, Optional, Tuple
from sqlalchemy import desc, asc
from sqlalchemy.orm import Session

from backend.app.core.exceptions import CrossTenantAccessDeniedException
from backend.app.models.asset import DeceptiveAsset
from backend.app.models.attacker import AttackerProfile
from backend.app.models.event import AttackEvent
from backend.app.models.session import AttackerSession
from backend.app.schemas.asset import AssetCreate, AssetUpdate, AssetStatus, VALID_STATUS_TRANSITIONS


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

    # --------------------------------------------------------------------------
    # Deceptive Asset Operations
    # --------------------------------------------------------------------------

    def get_asset(self, asset_id: str) -> Optional[DeceptiveAsset]:
        """Fetch a deceptive asset by ID, rejecting cross-tenant attempts."""
        clean_id = asset_id.strip()
        asset = self.db.query(DeceptiveAsset).filter(DeceptiveAsset.asset_id == clean_id).first()
        if not asset:
            return None
        if asset.tenant_id != self.tenant_id:
            raise CrossTenantAccessDeniedException(
                f"Access denied: asset '{clean_id}' belongs to tenant '{asset.tenant_id}', not '{self.tenant_id}'"
            )
        return asset

    def list_assets(
        self,
        page: int = 1,
        page_size: int = 20,
        asset_type: Optional[str] = None,
        status_filter: Optional[str] = None,
        environment: Optional[str] = None,
        search: Optional[str] = None,
    ) -> Tuple[List[DeceptiveAsset], int]:
        """Query deceptive assets strictly constrained to self.tenant_id."""
        query = self.db.query(DeceptiveAsset).filter(DeceptiveAsset.tenant_id == self.tenant_id)

        if asset_type:
            query = query.filter(DeceptiveAsset.asset_type == asset_type.strip().lower())
        if status_filter:
            query = query.filter(DeceptiveAsset.status == status_filter.strip().lower())
        if environment:
            query = query.filter(DeceptiveAsset.environment == environment.strip().lower())
        if search:
            term = f"%{search.strip()}%"
            query = query.filter(
                (DeceptiveAsset.name.ilike(term)) | (DeceptiveAsset.asset_id.ilike(term))
            )

        query = query.order_by(desc(DeceptiveAsset.created_at))
        total = query.count()
        offset = (page - 1) * page_size
        items = query.offset(offset).limit(page_size).all()
        return items, total

    def create_asset(self, payload: AssetCreate) -> DeceptiveAsset:
        """Register a new deceptive asset under self.tenant_id, rejecting cross-tenant targets."""
        # 1. Enforce that payload cannot target a foreign tenant
        if payload.tenant_id and payload.tenant_id.strip() != self.tenant_id:
            raise CrossTenantAccessDeniedException(
                f"Unauthorized: cannot register asset under tenant '{payload.tenant_id}' using authenticated tenant context '{self.tenant_id}'"
            )

        clean_id = payload.asset_id.strip()

        # 2. Prevent duplicate asset_id globally or within tenant
        existing = self.db.query(DeceptiveAsset).filter(DeceptiveAsset.asset_id == clean_id).first()
        if existing:
            if existing.tenant_id != self.tenant_id:
                raise CrossTenantAccessDeniedException(
                    f"Asset ID '{clean_id}' is already registered under another tenant"
                )
            raise ValueError(f"Asset with ID '{clean_id}' already exists in tenant '{self.tenant_id}'")

        now = datetime.now(timezone.utc)
        asset = DeceptiveAsset(
            asset_id=clean_id,
            tenant_id=self.tenant_id,
            name=payload.name.strip(),
            asset_type=payload.asset_type.strip().lower(),
            description=payload.description.strip() if payload.description else None,
            deployment_id=payload.deployment_id.strip() if payload.deployment_id else None,
            environment=payload.environment.strip().lower() if payload.environment else "production",
            status=payload.status.strip().lower() if payload.status else AssetStatus.ACTIVE.value,
            config_metadata=payload.config_metadata or {},
            created_at=now,
            updated_at=now,
        )
        self.db.add(asset)
        self.db.commit()
        self.db.refresh(asset)
        return asset

    def update_asset(self, asset_id: str, payload: AssetUpdate) -> Optional[DeceptiveAsset]:
        """Update an existing asset with validation of tenant ownership and status transitions."""
        asset = self.get_asset(asset_id)
        if not asset:
            return None

        # Validate status transitions if status is being updated
        if payload.status is not None:
            new_status_str = payload.status.strip().lower()
            try:
                current_status = AssetStatus(asset.status)
                new_status = AssetStatus(new_status_str)
                allowed_transitions = VALID_STATUS_TRANSITIONS.get(current_status, set())
                if new_status != current_status and new_status not in allowed_transitions:
                    raise ValueError(
                        f"Invalid status transition from '{asset.status}' to '{new_status_str}'. "
                        f"Allowed transitions: {[s.value for s in allowed_transitions]}"
                    )
            except ValueError as ve:
                if "Invalid status transition" in str(ve):
                    raise
                # Fallback if unknown custom status
                pass
            asset.status = new_status_str

        if payload.name is not None:
            asset.name = payload.name.strip()
        if payload.description is not None:
            asset.description = payload.description.strip() if payload.description else None
        if payload.deployment_id is not None:
            asset.deployment_id = payload.deployment_id.strip() if payload.deployment_id else None
        if payload.environment is not None:
            asset.environment = payload.environment.strip().lower()
        if payload.config_metadata is not None:
            asset.config_metadata = payload.config_metadata

        asset.updated_at = datetime.now(timezone.utc)
        self.db.commit()
        self.db.refresh(asset)
        return asset

    def delete_asset(self, asset_id: str, hard_delete: bool = False) -> bool:
        """Decommission or permanently remove an asset with tenant ownership enforcement."""
        asset = self.get_asset(asset_id)
        if not asset:
            return False

        if hard_delete:
            self.db.delete(asset)
        else:
            asset.status = AssetStatus.DECOMMISSIONED.value
            asset.updated_at = datetime.now(timezone.utc)

        self.db.commit()
        return True
