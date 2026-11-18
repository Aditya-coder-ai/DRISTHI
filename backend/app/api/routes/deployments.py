"""Deployment Registration and Lifecycle API endpoints."""

from math import ceil
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status

from backend.app.api.deps import get_tenant_data_access
from backend.app.core.exceptions import CrossTenantAccessDeniedException
from backend.app.core.security import verify_service_api_key
from backend.app.schemas.deployment import (
    DeploymentRegisterRequest,
    DeploymentHeartbeatRequest,
    DeploymentResponse,
    DeploymentUpdate,
    PaginatedDeploymentsResponse,
)
from backend.app.services.tenant_data_access import TenantDataAccess

router = APIRouter()


@router.post(
    "/deployments/register",
    response_model=DeploymentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register or update a deceptive asset deployment (Self-Registration)",
)
def register_deployment(
    payload: DeploymentRegisterRequest,
    data_access: TenantDataAccess = Depends(get_tenant_data_access),
    _authorized: bool = Depends(verify_service_api_key),
):
    """Allows deployed honeypots and deception services to register with the central backend.
    
    Supports idempotent upsert registration. Verifies that the referenced asset_id exists
    and belongs to the authenticated tenant.
    """
    try:
        deployment = data_access.register_deployment(payload)
        return deployment.to_dict()
    except CrossTenantAccessDeniedException as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )


@router.get(
    "/deployments",
    response_model=PaginatedDeploymentsResponse,
    summary="List registered deployments for the tenant",
)
def list_deployments(
    data_access: TenantDataAccess = Depends(get_tenant_data_access),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    limit: Optional[int] = Query(None, ge=1, le=100, description="Alias for page_size"),
    asset_type: Optional[str] = Query(None, description="Filter by asset type (e.g. ssh_honeypot, honeytoken)"),
    status: Optional[str] = Query(None, description="Filter by status (registered, active, inactive, failed, decommissioned)"),
    environment: Optional[str] = Query(None, description="Filter by environment (production, staging, edge)"),
    asset_id: Optional[str] = Query(None, description="Filter by referenced asset ID"),
):
    effective_page_size = limit if limit is not None else page_size
    items, total = data_access.list_deployments(
        page=page,
        page_size=effective_page_size,
        asset_type=asset_type,
        status_filter=status,
        environment=environment,
        asset_id=asset_id,
    )

    total_pages = ceil(total / effective_page_size) if total > 0 else 1

    return PaginatedDeploymentsResponse(
        total=total,
        page=page,
        page_size=effective_page_size,
        limit=effective_page_size,
        total_pages=total_pages,
        items=[it.to_dict() for it in items],
    )


@router.get(
    "/deployments/{deployment_id}",
    response_model=DeploymentResponse,
    summary="Retrieve deployment registration details",
)
def get_deployment(
    deployment_id: str,
    data_access: TenantDataAccess = Depends(get_tenant_data_access),
):
    try:
        deployment = data_access.get_deployment(deployment_id)
    except CrossTenantAccessDeniedException as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        )

    if not deployment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Deployment '{deployment_id}' not found",
        )
    return deployment.to_dict()


@router.put(
    "/deployments/{deployment_id}",
    response_model=DeploymentResponse,
    summary="Update deployment status or configuration",
)
def update_deployment(
    deployment_id: str,
    payload: DeploymentUpdate,
    data_access: TenantDataAccess = Depends(get_tenant_data_access),
):
    try:
        deployment = data_access.update_deployment(deployment_id, payload)
    except CrossTenantAccessDeniedException as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )

    if not deployment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Deployment '{deployment_id}' not found",
        )
    return deployment.to_dict()


@router.post(
    "/deployments/{deployment_id}/heartbeat",
    response_model=DeploymentResponse,
    summary="Record deployment heartbeat and update status",
)
def record_heartbeat(
    deployment_id: str,
    payload: Optional[DeploymentHeartbeatRequest] = None,
    data_access: TenantDataAccess = Depends(get_tenant_data_access),
    _authorized: bool = Depends(verify_service_api_key),
):
    try:
        status_val = payload.status if payload else None
        version_val = payload.version if payload else None
        metadata_val = payload.deploy_metadata if payload else None
        deployment = data_access.record_heartbeat(
            deployment_id=deployment_id,
            status=status_val,
            version=version_val,
            metadata=metadata_val,
        )
    except CrossTenantAccessDeniedException as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )

    if not deployment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Deployment '{deployment_id}' not found",
        )
    return deployment.to_dict()
