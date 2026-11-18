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
import uuid
from math import ceil
from typing import List, Optional, Tuple
from sqlalchemy import desc, asc
from sqlalchemy.orm import Session

from backend.app.core.exceptions import CrossTenantAccessDeniedException
from backend.app.models.asset import DeceptiveAsset
from backend.app.models.attacker import AttackerProfile
from backend.app.models.deployment import Deployment
from backend.app.models.event import AttackEvent
from backend.app.models.honeytoken import Honeytoken
from backend.app.models.integration import IntegrationConfig
from backend.app.models.session import AttackerSession
from backend.app.schemas.asset import AssetCreate, AssetUpdate, AssetStatus, VALID_STATUS_TRANSITIONS
from backend.app.schemas.deployment import (
    DeploymentRegisterRequest,
    DeploymentUpdate,
    DeploymentStatus,
    VALID_DEPLOYMENT_STATUS_TRANSITIONS,
)
from backend.app.schemas.honeytoken import (
    HoneytokenCreate,
    HoneytokenUpdate,
    HoneytokenStatus,
    VALID_HONEYTOKEN_STATUS_TRANSITIONS,
)
from backend.app.schemas.integration import (
    IntegrationCreate,
    IntegrationUpdate,
    IntegrationStatus,
    mask_secret,
    hash_secret,
)


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

    # --------------------------------------------------------------------------
    # Honeytoken Operations
    # --------------------------------------------------------------------------

    def get_honeytoken(self, token_id: str) -> Optional[Honeytoken]:
        """Fetch a honeytoken by ID, validating tenant ownership and dynamically updating expiration."""
        from backend.app.services.honeytoken_service import HoneytokenService
        service = HoneytokenService(self.db, self.tenant_id)
        return service.get_honeytoken(token_id)

    def list_honeytokens(
        self,
        page: int = 1,
        page_size: int = 50,
        asset_id: Optional[str] = None,
        token_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> Tuple[List[Honeytoken], int]:
        """List honeytokens strictly scoped to self.tenant_id."""
        now = datetime.now(timezone.utc)
        query = self.db.query(Honeytoken).filter(Honeytoken.tenant_id == self.tenant_id)

        if asset_id:
            query = query.filter(Honeytoken.asset_id == asset_id.strip())
        if token_type:
            query = query.filter(Honeytoken.token_type == token_type.strip().lower())
        if status:
            query = query.filter(Honeytoken.status == status.strip().lower())

        query = query.order_by(desc(Honeytoken.created_at))
        total = query.count()
        offset = (page - 1) * page_size
        items = query.offset(offset).limit(page_size).all()

        # Dynamic expiration check on retrieved items
        for item in items:
            if item.status == HoneytokenStatus.ACTIVE.value and item.expires_at:
                exp = item.expires_at if item.expires_at.tzinfo else item.expires_at.replace(tzinfo=timezone.utc)
                if exp <= now:
                    item.status = HoneytokenStatus.EXPIRED.value
                    item.updated_at = now
        self.db.commit()

        return items, total

    def create_honeytoken(self, payload: HoneytokenCreate) -> Tuple[Honeytoken, Optional[dict]]:
        """Register a honeytoken with strict tenant isolation and asset verification."""
        from backend.app.services.honeytoken_service import HoneytokenService
        service = HoneytokenService(self.db, self.tenant_id)
        return service.register_honeytoken(payload)

    def update_honeytoken(self, token_id: str, payload: HoneytokenUpdate) -> Optional[Honeytoken]:
        """Update a honeytoken with tenant ownership validation and allowed status transition checks."""
        token = self.get_honeytoken(token_id)
        if not token:
            return None

        if payload.status is not None:
            new_status_str = payload.status.strip().lower()
            try:
                current_status = HoneytokenStatus(token.status)
                new_status = HoneytokenStatus(new_status_str)
                allowed_transitions = VALID_HONEYTOKEN_STATUS_TRANSITIONS.get(current_status, set())
                if new_status != current_status and new_status not in allowed_transitions:
                    raise ValueError(
                        f"Invalid status transition from '{token.status}' to '{new_status_str}'. "
                        f"Allowed transitions: {[s.value for s in allowed_transitions]}"
                    )
            except ValueError as ve:
                if "Invalid status transition" in str(ve):
                    raise
                pass
            token.status = new_status_str

        if payload.name is not None:
            token.name = payload.name.strip()
        if payload.description is not None:
            token.description = payload.description.strip() if payload.description else None
        if payload.metadata is not None:
            token.token_metadata = payload.metadata
        if payload.expires_at is not None:
            token.expires_at = payload.expires_at

        token.updated_at = datetime.now(timezone.utc)
        self.db.commit()
        self.db.refresh(token)
        return token

    def delete_honeytoken(self, token_id: str, hard_delete: bool = False) -> bool:
        """Revoke or permanently delete a honeytoken with tenant ownership verification."""
        token = self.get_honeytoken(token_id)
        if not token:
            return False

        if hard_delete:
            self.db.delete(token)
        else:
            now = datetime.now(timezone.utc)
            token.status = HoneytokenStatus.REVOKED.value
            meta = dict(token.token_metadata or {})
            meta["revoked_at"] = now.isoformat()
            token.token_metadata = meta
            token.updated_at = now

        self.db.commit()
        return True

    # --------------------------------------------------------------------------
    # Deployment Registration Operations
    # --------------------------------------------------------------------------

    def get_deployment(self, deployment_id: str) -> Optional[Deployment]:
        """Fetch a deployment by ID, rejecting cross-tenant attempts."""
        clean_id = deployment_id.strip()
        deployment = self.db.query(Deployment).filter(Deployment.deployment_id == clean_id).first()
        if not deployment:
            return None
        if deployment.tenant_id != self.tenant_id:
            raise CrossTenantAccessDeniedException(
                f"Access denied: deployment '{clean_id}' belongs to tenant '{deployment.tenant_id}', not '{self.tenant_id}'"
            )
        return deployment

    def list_deployments(
        self,
        page: int = 1,
        page_size: int = 20,
        asset_type: Optional[str] = None,
        status_filter: Optional[str] = None,
        environment: Optional[str] = None,
        asset_id: Optional[str] = None,
    ) -> Tuple[List[Deployment], int]:
        """Query deployments strictly constrained to self.tenant_id."""
        query = self.db.query(Deployment).filter(Deployment.tenant_id == self.tenant_id)

        if asset_type:
            query = query.filter(Deployment.asset_type == asset_type.strip().lower())
        if status_filter:
            query = query.filter(Deployment.status == status_filter.strip().lower())
        if environment:
            query = query.filter(Deployment.environment == environment.strip().lower())
        if asset_id:
            query = query.filter(Deployment.asset_id == asset_id.strip())

        query = query.order_by(desc(Deployment.registered_at))
        total = query.count()
        offset = (page - 1) * page_size
        items = query.offset(offset).limit(page_size).all()
        return items, total

    def register_deployment(self, payload: DeploymentRegisterRequest) -> Deployment:
        """Register a new deployment or update an existing one (upsert-safe).

        Validates that the referenced asset_id exists and belongs to the current tenant.
        """
        clean_deploy_id = payload.deployment_id.strip()
        clean_asset_id = payload.asset_id.strip()

        # Verify the referenced asset exists and belongs to this tenant
        asset = self.get_asset(clean_asset_id)
        if not asset:
            raise ValueError(f"Asset '{clean_asset_id}' not found in tenant '{self.tenant_id}'")

        # Check if deployment already exists (upsert behavior)
        existing = self.db.query(Deployment).filter(
            Deployment.deployment_id == clean_deploy_id
        ).first()

        now = datetime.now(timezone.utc)

        if existing:
            # Enforce tenant isolation on existing deployment
            if existing.tenant_id != self.tenant_id:
                raise CrossTenantAccessDeniedException(
                    f"Deployment '{clean_deploy_id}' is already registered under another tenant"
                )
            # Update existing deployment (re-registration / upsert)
            existing.asset_id = clean_asset_id
            existing.asset_type = payload.asset_type.strip().lower()
            existing.environment = payload.environment.strip().lower() if payload.environment else existing.environment
            existing.version = payload.version.strip() if payload.version else existing.version
            existing.hostname = payload.hostname.strip() if payload.hostname else existing.hostname
            existing.ip_address = payload.ip_address.strip() if payload.ip_address else existing.ip_address
            existing.port = payload.port if payload.port is not None else existing.port
            existing.deploy_metadata = payload.deploy_metadata or existing.deploy_metadata
            existing.last_heartbeat_at = now
            existing.updated_at = now
            self.db.commit()
            self.db.refresh(existing)
            return existing

        # Create new deployment
        deployment = Deployment(
            deployment_id=clean_deploy_id,
            asset_id=clean_asset_id,
            tenant_id=self.tenant_id,
            asset_type=payload.asset_type.strip().lower(),
            environment=payload.environment.strip().lower() if payload.environment else "production",
            version=payload.version.strip() if payload.version else None,
            hostname=payload.hostname.strip() if payload.hostname else None,
            ip_address=payload.ip_address.strip() if payload.ip_address else None,
            port=payload.port,
            status=DeploymentStatus.REGISTERED.value,
            registered_at=now,
            last_heartbeat_at=None,
            deploy_metadata=payload.deploy_metadata or {},
            created_at=now,
            updated_at=now,
        )
        self.db.add(deployment)
        self.db.commit()
        self.db.refresh(deployment)
        return deployment

    def update_deployment(self, deployment_id: str, payload: DeploymentUpdate) -> Optional[Deployment]:
        """Update an existing deployment with tenant ownership and status transition validation."""
        deployment = self.get_deployment(deployment_id)
        if not deployment:
            return None

        # Validate status transitions
        if payload.status is not None:
            new_status_str = payload.status.strip().lower()
            try:
                current_status = DeploymentStatus(deployment.status)
                new_status = DeploymentStatus(new_status_str)
                allowed = VALID_DEPLOYMENT_STATUS_TRANSITIONS.get(current_status, set())
                if new_status != current_status and new_status not in allowed:
                    raise ValueError(
                        f"Invalid status transition from '{deployment.status}' to '{new_status_str}'. "
                        f"Allowed transitions: {[s.value for s in allowed]}"
                    )
            except ValueError as ve:
                if "Invalid status transition" in str(ve):
                    raise
                pass
            deployment.status = new_status_str

        if payload.environment is not None:
            deployment.environment = payload.environment.strip().lower()
        if payload.version is not None:
            deployment.version = payload.version.strip() if payload.version else None
        if payload.hostname is not None:
            deployment.hostname = payload.hostname.strip() if payload.hostname else None
        if payload.ip_address is not None:
            deployment.ip_address = payload.ip_address.strip() if payload.ip_address else None
        if payload.port is not None:
            deployment.port = payload.port
        if payload.deploy_metadata is not None:
            deployment.deploy_metadata = payload.deploy_metadata

        deployment.updated_at = datetime.now(timezone.utc)
        self.db.commit()
        self.db.refresh(deployment)
        return deployment

    def record_heartbeat(self, deployment_id: str, status: Optional[str] = None, version: Optional[str] = None, metadata: Optional[dict] = None) -> Optional[Deployment]:
        """Record a heartbeat for a deployment, updating last_heartbeat_at and optionally status/version."""
        deployment = self.get_deployment(deployment_id)
        if not deployment:
            return None

        now = datetime.now(timezone.utc)
        deployment.last_heartbeat_at = now
        deployment.updated_at = now

        if status is not None:
            new_status_str = status.strip().lower()
            try:
                current_status = DeploymentStatus(deployment.status)
                new_status = DeploymentStatus(new_status_str)
                allowed = VALID_DEPLOYMENT_STATUS_TRANSITIONS.get(current_status, set())
                if new_status != current_status and new_status not in allowed:
                    raise ValueError(
                        f"Invalid status transition from '{deployment.status}' to '{new_status_str}'. "
                        f"Allowed transitions: {[s.value for s in allowed]}"
                    )
            except ValueError as ve:
                if "Invalid status transition" in str(ve):
                    raise
                pass
            deployment.status = new_status_str

        if version is not None:
            deployment.version = version.strip()
        if metadata is not None:
            deployment.deploy_metadata = metadata

        self.db.commit()
        self.db.refresh(deployment)
        return deployment

    # --------------------------------------------------------------------------
    # Integration Configuration Operations
    # --------------------------------------------------------------------------

    def get_integration(self, integration_id: str) -> Optional[IntegrationConfig]:
        """Fetch an integration configuration by ID, rejecting cross-tenant attempts."""
        clean_id = integration_id.strip()
        integration = self.db.query(IntegrationConfig).filter(
            IntegrationConfig.integration_id == clean_id
        ).first()
        if not integration:
            return None
        if integration.tenant_id != self.tenant_id:
            raise CrossTenantAccessDeniedException(
                f"Access denied: integration '{clean_id}' belongs to tenant '{integration.tenant_id}', not '{self.tenant_id}'"
            )
        return integration

    def list_integrations(
        self,
        page: int = 1,
        page_size: int = 20,
        integration_type: Optional[str] = None,
        enabled: Optional[bool] = None,
        status_filter: Optional[str] = None,
        search: Optional[str] = None,
    ) -> Tuple[List[IntegrationConfig], int]:
        """Query integration configurations strictly constrained to self.tenant_id."""
        query = self.db.query(IntegrationConfig).filter(IntegrationConfig.tenant_id == self.tenant_id)

        if integration_type:
            query = query.filter(IntegrationConfig.integration_type == integration_type.strip().lower())
        if enabled is not None:
            query = query.filter(IntegrationConfig.enabled == enabled)
        if status_filter:
            query = query.filter(IntegrationConfig.status == status_filter.strip().lower())
        if search:
            term = f"%{search.strip()}%"
            query = query.filter(
                (IntegrationConfig.name.ilike(term)) | (IntegrationConfig.integration_id.ilike(term))
            )

        query = query.order_by(desc(IntegrationConfig.created_at))
        total = query.count()
        offset = (page - 1) * page_size
        items = query.offset(offset).limit(page_size).all()
        return items, total

    def create_integration(self, payload: IntegrationCreate) -> IntegrationConfig:
        """Create a new integration configuration with secret masking and tenant isolation."""
        clean_id = payload.integration_id.strip() if payload.integration_id else f"intg-{payload.integration_type[:4]}-{uuid.uuid4().hex[:8]}"

        existing = self.db.query(IntegrationConfig).filter(
            IntegrationConfig.integration_id == clean_id
        ).first()
        if existing:
            if existing.tenant_id != self.tenant_id:
                raise CrossTenantAccessDeniedException(
                    f"Integration ID '{clean_id}' already registered under another tenant"
                )
            raise ValueError(f"Integration with ID '{clean_id}' already exists in tenant '{self.tenant_id}'")

        now = datetime.now(timezone.utc)
        secret_masked = None
        secret_hash_val = None
        secret_storage_val = None

        if payload.secret:
            secret_masked = mask_secret(payload.secret)
            secret_hash_val = hash_secret(payload.secret)
            secret_storage_val = f"enc:v1:{secret_hash_val[:16]}:{uuid.uuid4().hex[:8]}"

        # Perform initial safe configuration validation
        is_valid, validation_details = self._validate_config(
            payload.integration_type,
            payload.config_metadata,
            has_secret=bool(payload.secret),
        )
        initial_status = IntegrationStatus.VERIFIED.value if is_valid else (
            IntegrationStatus.CONFIGURED.value if payload.enabled else IntegrationStatus.DISABLED.value
        )

        integration = IntegrationConfig(
            integration_id=clean_id,
            tenant_id=self.tenant_id,
            name=payload.name.strip(),
            integration_type=payload.integration_type.strip().lower(),
            enabled=payload.enabled,
            status=initial_status,
            config_metadata=payload.config_metadata,
            secret_masked=secret_masked,
            secret_hash=secret_hash_val,
            secret_storage=secret_storage_val,
            last_validated_at=now if is_valid else None,
            validation_details=validation_details,
            created_at=now,
            updated_at=now,
        )
        self.db.add(integration)
        self.db.commit()
        self.db.refresh(integration)
        return integration

    def update_integration(self, integration_id: str, payload: IntegrationUpdate) -> Optional[IntegrationConfig]:
        """Update an existing integration with tenant verification and optional secret rotation/revocation."""
        integration = self.get_integration(integration_id)
        if not integration:
            return None

        now = datetime.now(timezone.utc)

        if payload.name is not None:
            integration.name = payload.name.strip()
        if payload.config_metadata is not None:
            integration.config_metadata = payload.config_metadata
        if payload.enabled is not None:
            integration.enabled = payload.enabled
            if not payload.enabled:
                integration.status = IntegrationStatus.DISABLED.value
            elif integration.status == IntegrationStatus.DISABLED.value:
                integration.status = IntegrationStatus.CONFIGURED.value
        if payload.status is not None:
            integration.status = payload.status.strip().lower()

        # Handle secret rotation or revocation
        if payload.revoke_secret:
            integration.secret_masked = None
            integration.secret_hash = None
            integration.secret_storage = None
        elif payload.secret:
            integration.secret_masked = mask_secret(payload.secret)
            integration.secret_hash = hash_secret(payload.secret)
            integration.secret_storage = f"enc:v1:{integration.secret_hash[:16]}:{uuid.uuid4().hex[:8]}"

        integration.updated_at = now
        self.db.commit()
        self.db.refresh(integration)
        return integration

    def toggle_integration(self, integration_id: str, enabled: Optional[bool] = None) -> Optional[IntegrationConfig]:
        """Enable or disable an integration configuration."""
        integration = self.get_integration(integration_id)
        if not integration:
            return None

        new_enabled = enabled if enabled is not None else not integration.enabled
        integration.enabled = new_enabled
        if not new_enabled:
            integration.status = IntegrationStatus.DISABLED.value
        elif integration.status == IntegrationStatus.DISABLED.value:
            integration.status = IntegrationStatus.CONFIGURED.value

        integration.updated_at = datetime.now(timezone.utc)
        self.db.commit()
        self.db.refresh(integration)
        return integration

    def delete_integration(self, integration_id: str) -> bool:
        """Permanently remove an integration configuration with tenant ownership verification."""
        integration = self.get_integration(integration_id)
        if not integration:
            return False

        self.db.delete(integration)
        self.db.commit()
        return True

    def validate_integration(self, integration_id: str) -> Tuple[bool, dict]:
        """Runs safe syntax and required fields validation on an integration without unauthorized external calls."""
        integration = self.get_integration(integration_id)
        if not integration:
            raise ValueError(f"Integration '{integration_id}' not found in tenant '{self.tenant_id}'")

        is_valid, validation_details = self._validate_config(
            integration.integration_type,
            integration.config_metadata or {},
            has_secret=bool(integration.secret_hash or integration.secret_storage),
        )

        now = datetime.now(timezone.utc)
        integration.last_validated_at = now
        integration.validation_details = validation_details
        integration.status = IntegrationStatus.VERIFIED.value if is_valid else IntegrationStatus.ERROR.value
        integration.updated_at = now

        self.db.commit()
        self.db.refresh(integration)
        return is_valid, validation_details

    @staticmethod
    def _validate_config(integration_type: str, config: dict, has_secret: bool) -> Tuple[bool, dict]:
        details = {"errors": [], "warnings": [], "validated_fields": []}
        itype = integration_type.strip().lower()

        if itype == "webhook":
            url = config.get("url") or config.get("endpoint_url")
            if not url:
                details["errors"].append("Missing required field 'url'")
            elif not isinstance(url, str) or not (url.startswith("http://") or url.startswith("https://")):
                details["errors"].append("Field 'url' must be a valid HTTP or HTTPS URL")
            else:
                details["validated_fields"].append("url")
                if url.startswith("http://") and "localhost" not in url and "127.0.0.1" not in url:
                    details["warnings"].append("Insecure HTTP endpoint detected for external webhook")
            method = config.get("http_method", "POST")
            if method.upper() not in ["POST", "PUT", "PATCH"]:
                details["errors"].append(f"Unsupported http_method '{method}'. Allowed: POST, PUT, PATCH")
            else:
                details["validated_fields"].append("http_method")

        elif itype == "siem":
            host = config.get("host") or config.get("server_url")
            if not host:
                details["errors"].append("Missing required field 'host' or 'server_url'")
            else:
                details["validated_fields"].append("host")
            port = config.get("port")
            if port is not None:
                if not isinstance(port, int) or port < 1 or port > 65535:
                    details["errors"].append("Field 'port' must be an integer between 1 and 65535")
                else:
                    details["validated_fields"].append("port")
            fmt = config.get("format", "json").lower()
            if fmt not in ["json", "cef", "syslog", "leef"]:
                details["errors"].append(f"Unsupported SIEM format '{fmt}'. Allowed: json, cef, syslog, leef")
            else:
                details["validated_fields"].append("format")

        elif itype == "security_monitoring":
            target = config.get("target_system") or config.get("endpoint_url")
            if not target:
                details["errors"].append("Missing required field 'target_system' or 'endpoint_url'")
            else:
                details["validated_fields"].append("target_system")

        elif itype == "cloud_integration":
            provider = (config.get("provider") or "").lower()
            if not provider:
                details["errors"].append("Missing required field 'provider'")
            elif provider not in ["aws", "azure", "gcp"]:
                details["errors"].append(f"Unsupported cloud provider '{provider}'. Allowed: aws, azure, gcp")
            else:
                details["validated_fields"].append("provider")
            if not config.get("region") and not config.get("account_id") and not config.get("project_id"):
                details["warnings"].append("No specific region or cloud account identifier specified")

        is_valid = len(details["errors"]) == 0
        return is_valid, details
