"""Deceptive Asset Registry API endpoints."""

from math import ceil
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status

from backend.app.api.deps import get_tenant_data_access
from backend.app.core.exceptions import CrossTenantAccessDeniedException
from backend.app.schemas.asset import (
    AssetCreate,
    AssetUpdate,
    AssetResponse,
    PaginatedAssetsResponse,
)
from backend.app.services.tenant_data_access import TenantDataAccess

router = APIRouter()


@router.post(
    "/assets",
    response_model=AssetResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new deceptive asset",
)
def register_asset(
    payload: AssetCreate,
    data_access: TenantDataAccess = Depends(get_tenant_data_access),
):
    try:
        asset = data_access.create_asset(payload)
        return asset.to_dict()
    except CrossTenantAccessDeniedException as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        )


@router.get(
    "/assets",
    response_model=PaginatedAssetsResponse,
    summary="List registered deceptive assets",
)
def list_assets(
    data_access: TenantDataAccess = Depends(get_tenant_data_access),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    limit: Optional[int] = Query(None, ge=1, le=100, description="Alias for page_size"),
    asset_type: Optional[str] = Query(None, description="Filter by asset type (e.g. ssh_honeypot, honeytoken)"),
    status: Optional[str] = Query(None, description="Filter by status (active, inactive, suspended, decommissioned)"),
    environment: Optional[str] = Query(None, description="Filter by environment (production, staging, edge)"),
    search: Optional[str] = Query(None, description="Search by name or asset ID"),
):
    effective_page_size = limit if limit is not None else page_size
    items, total = data_access.list_assets(
        page=page,
        page_size=effective_page_size,
        asset_type=asset_type,
        status_filter=status,
        environment=environment,
        search=search,
    )

    total_pages = ceil(total / effective_page_size) if total > 0 else 1

    return PaginatedAssetsResponse(
        total=total,
        page=page,
        page_size=effective_page_size,
        limit=effective_page_size,
        total_pages=total_pages,
        items=[it.to_dict() for it in items],
    )


@router.get(
    "/assets/{asset_id}",
    response_model=AssetResponse,
    summary="Retrieve deceptive asset details",
)
def get_asset(
    asset_id: str,
    data_access: TenantDataAccess = Depends(get_tenant_data_access),
):
    try:
        asset = data_access.get_asset(asset_id)
    except CrossTenantAccessDeniedException as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        )

    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Deceptive asset '{asset_id}' not found",
        )
    return asset.to_dict()


@router.put(
    "/assets/{asset_id}",
    response_model=AssetResponse,
    summary="Update deceptive asset properties or status",
)
def update_asset(
    asset_id: str,
    payload: AssetUpdate,
    data_access: TenantDataAccess = Depends(get_tenant_data_access),
):
    try:
        asset = data_access.update_asset(asset_id, payload)
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

    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Deceptive asset '{asset_id}' not found",
        )
    return asset.to_dict()


@router.delete(
    "/assets/{asset_id}",
    summary="Decommission or permanently delete a deceptive asset",
)
def delete_asset(
    asset_id: str,
    hard_delete: bool = Query(False, description="Set True for physical deletion, False for decommission"),
    data_access: TenantDataAccess = Depends(get_tenant_data_access),
):
    try:
        success = data_access.delete_asset(asset_id, hard_delete=hard_delete)
    except CrossTenantAccessDeniedException as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        )

    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Deceptive asset '{asset_id}' not found",
        )

    return {
        "status": "deleted" if hard_delete else "decommissioned",
        "asset_id": asset_id,
        "tenant_id": data_access.tenant_id,
    }
