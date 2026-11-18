"""Integration Configuration API endpoints."""

from math import ceil
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status

from backend.app.api.deps import get_tenant_data_access
from backend.app.core.exceptions import CrossTenantAccessDeniedException
from backend.app.schemas.integration import (
    IntegrationCreate,
    IntegrationUpdate,
    IntegrationResponse,
    PaginatedIntegrationsResponse,
    IntegrationValidationResult,
)
from backend.app.services.tenant_data_access import TenantDataAccess

router = APIRouter()


@router.post(
    "/integrations",
    response_model=IntegrationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new external integration configuration",
)
def create_integration(
    payload: IntegrationCreate,
    data_access: TenantDataAccess = Depends(get_tenant_data_access),
):
    """Creates a new external SIEM, Webhook, Security Monitoring, or Cloud integration configuration.
    
    Any provided secret/credential is securely hashed and stored; it is never exposed in responses or logs.
    """
    try:
        integration = data_access.create_integration(payload)
        return integration.to_dict()
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
    "/integrations",
    response_model=PaginatedIntegrationsResponse,
    summary="List external integration configurations",
)
def list_integrations(
    data_access: TenantDataAccess = Depends(get_tenant_data_access),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    limit: Optional[int] = Query(None, ge=1, le=100, description="Alias for page_size"),
    integration_type: Optional[str] = Query(None, description="Filter by type (webhook, siem, security_monitoring, cloud_integration)"),
    enabled: Optional[bool] = Query(None, description="Filter by enabled status"),
    status: Optional[str] = Query(None, description="Filter by status (configured, verified, error, disabled)"),
    search: Optional[str] = Query(None, description="Search by name or integration ID"),
):
    effective_page_size = limit if limit is not None else page_size
    items, total = data_access.list_integrations(
        page=page,
        page_size=effective_page_size,
        integration_type=integration_type,
        enabled=enabled,
        status_filter=status,
        search=search,
    )

    total_pages = ceil(total / effective_page_size) if total > 0 else 1

    return PaginatedIntegrationsResponse(
        total=total,
        page=page,
        page_size=effective_page_size,
        limit=effective_page_size,
        total_pages=total_pages,
        items=[it.to_dict() for it in items],
    )


@router.get(
    "/integrations/{integration_id}",
    response_model=IntegrationResponse,
    summary="Retrieve integration configuration details",
)
def get_integration(
    integration_id: str,
    data_access: TenantDataAccess = Depends(get_tenant_data_access),
):
    try:
        integration = data_access.get_integration(integration_id)
    except CrossTenantAccessDeniedException as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        )

    if not integration:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Integration '{integration_id}' not found",
        )
    return integration.to_dict()


@router.put(
    "/integrations/{integration_id}",
    response_model=IntegrationResponse,
    summary="Update integration configuration or rotate/revoke secrets",
)
def update_integration(
    integration_id: str,
    payload: IntegrationUpdate,
    data_access: TenantDataAccess = Depends(get_tenant_data_access),
):
    try:
        integration = data_access.update_integration(integration_id, payload)
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

    if not integration:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Integration '{integration_id}' not found",
        )
    return integration.to_dict()


@router.patch(
    "/integrations/{integration_id}/toggle",
    response_model=IntegrationResponse,
    summary="Toggle enabled/disabled state of an integration",
)
def toggle_integration(
    integration_id: str,
    enabled: Optional[bool] = Query(None, description="Explicit target state (True/False). If omitted, state is flipped."),
    data_access: TenantDataAccess = Depends(get_tenant_data_access),
):
    try:
        integration = data_access.toggle_integration(integration_id, enabled=enabled)
    except CrossTenantAccessDeniedException as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        )

    if not integration:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Integration '{integration_id}' not found",
        )
    return integration.to_dict()


@router.delete(
    "/integrations/{integration_id}",
    summary="Delete an integration configuration",
)
def delete_integration(
    integration_id: str,
    data_access: TenantDataAccess = Depends(get_tenant_data_access),
):
    try:
        success = data_access.delete_integration(integration_id)
    except CrossTenantAccessDeniedException as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        )

    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Integration '{integration_id}' not found",
        )

    return {
        "status": "deleted",
        "integration_id": integration_id,
        "tenant_id": data_access.tenant_id,
    }


@router.post(
    "/integrations/{integration_id}/validate",
    response_model=IntegrationValidationResult,
    summary="Safely validate integration configuration fields and syntax",
)
def validate_integration(
    integration_id: str,
    data_access: TenantDataAccess = Depends(get_tenant_data_access),
):
    """Performs safe syntax and semantic validation on the integration configuration.
    
    Verifies required fields according to integration type (webhook URL format, SIEM host/port/format,
    cloud provider/region) without firing unauthorized external network requests.
    """
    try:
        is_valid, details = data_access.validate_integration(integration_id)
        integration = data_access.get_integration(integration_id)
        return IntegrationValidationResult(
            integration_id=integration_id,
            is_valid=is_valid,
            status=integration.status,
            details=details,
            validated_at=integration.last_validated_at,
        )
    except CrossTenantAccessDeniedException as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )
