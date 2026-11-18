"""FastAPI Dependency Injection helpers."""

from typing import Generator, Optional
from fastapi import Depends, Header, Query
from sqlalchemy.orm import Session
from backend.app.core.config import settings
from backend.app.database.connection import get_db
from backend.app.services.analytics_service import AnalyticsService
from backend.app.services.asset_service import AssetService
from backend.app.services.attacker_service import AttackerService
from backend.app.services.honeytoken_service import HoneytokenService
from backend.app.services.ingestion_service import IngestionService
from backend.app.services.session_service import SessionService
from backend.app.services.tenant_data_access import TenantDataAccess
from backend.app.services.tenant_service import TenantService


def get_current_tenant(
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID"),
    tenant_id: Optional[str] = Query(None),
) -> str:
    """Extracts tenant context from X-Tenant-ID header, query parameter, or defaults to platform tenant."""
    if x_tenant_id and x_tenant_id.strip():
        return x_tenant_id.strip()
    if tenant_id and tenant_id.strip():
        return tenant_id.strip()
    return settings.DEFAULT_TENANT_ID


def get_tenant_data_access(
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
) -> TenantDataAccess:
    return TenantDataAccess(db=db, tenant_id=tenant_id)


def get_tenant_service(db: Session = Depends(get_db)) -> TenantService:
    return TenantService(db)


def get_ingestion_service(db: Session = Depends(get_db)) -> IngestionService:
    return IngestionService(db)


def get_analytics_service(
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
) -> AnalyticsService:
    return AnalyticsService(db, tenant_id=tenant_id)


def get_session_service(db: Session = Depends(get_db)) -> SessionService:
    return SessionService(db)


def get_attacker_service(db: Session = Depends(get_db)) -> AttackerService:
    return AttackerService(db)


def get_asset_service(db: Session = Depends(get_db)) -> AssetService:
    return AssetService(db)


def get_honeytoken_service(
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
) -> HoneytokenService:
    return HoneytokenService(db, tenant_id=tenant_id)

