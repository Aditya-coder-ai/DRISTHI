"""Tenant Management API Endpoints."""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from backend.app.api.deps import get_tenant_service
from backend.app.schemas.tenant import TenantCreate, TenantResponse
from backend.app.services.tenant_service import TenantService

router = APIRouter()


@router.post(
    "/tenants",
    response_model=TenantResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new tenant",
)
def create_tenant(payload: TenantCreate, tenant_service: TenantService = Depends(get_tenant_service)):
    try:
        tenant = tenant_service.create_tenant(payload)
        return tenant.to_dict()
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        )


@router.get(
    "/tenants",
    response_model=List[TenantResponse],
    summary="List all active tenants",
)
def list_tenants(tenant_service: TenantService = Depends(get_tenant_service)):
    tenants = tenant_service.list_tenants()
    return [t.to_dict() for t in tenants]


@router.get(
    "/tenants/{tenant_id}",
    response_model=TenantResponse,
    summary="Retrieve tenant information by ID",
)
def get_tenant(tenant_id: str, tenant_service: TenantService = Depends(get_tenant_service)):
    tenant = tenant_service.get_tenant(tenant_id)
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tenant '{tenant_id}' not found",
        )
    return tenant.to_dict()
