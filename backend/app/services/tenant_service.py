"""Tenant Management Service for DRISTHI Central Backend."""

from typing import List, Optional
from sqlalchemy.orm import Session
from backend.app.models.tenant import Tenant
from backend.app.schemas.tenant import TenantCreate


class TenantService:
    """Provides tenant lifecycle and identification operations."""

    def __init__(self, db: Session):
        self.db = db

    def get_or_create_tenant(self, tenant_id: str, name: Optional[str] = None) -> Tenant:
        """Retrieves an existing tenant or creates a new one with default metadata."""
        clean_id = tenant_id.strip()
        tenant = self.db.query(Tenant).filter(Tenant.tenant_id == clean_id).first()
        if not tenant:
            tenant = Tenant(
                tenant_id=clean_id,
                name=name or f"Tenant {clean_id}",
                description=f"Auto-provisioned tenant {clean_id}",
                is_active=True,
            )
            self.db.add(tenant)
            self.db.flush()
        return tenant

    def create_tenant(self, payload: TenantCreate) -> Tenant:
        clean_id = payload.tenant_id.strip()
        existing = self.db.query(Tenant).filter(Tenant.tenant_id == clean_id).first()
        if existing:
            raise ValueError(f"Tenant with ID '{clean_id}' already exists")
        tenant = Tenant(
            tenant_id=clean_id,
            name=payload.name.strip(),
            description=payload.description.strip() if payload.description else None,
            is_active=True,
        )
        self.db.add(tenant)
        self.db.commit()
        self.db.refresh(tenant)
        return tenant

    def get_tenant(self, tenant_id: str) -> Optional[Tenant]:
        return self.db.query(Tenant).filter(Tenant.tenant_id == tenant_id.strip()).first()

    def list_tenants(self) -> List[Tenant]:
        return self.db.query(Tenant).filter(Tenant.is_active.is_(True)).all()
