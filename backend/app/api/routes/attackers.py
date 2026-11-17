"""Attacker Profile endpoints."""

from math import ceil
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from backend.app.api.deps import get_tenant_data_access
from backend.app.core.exceptions import CrossTenantAccessDeniedException
from backend.app.schemas.attacker import PaginatedAttackersResponse, AttackerProfileResponse
from backend.app.services.tenant_data_access import TenantDataAccess

router = APIRouter()


@router.get("/attackers", response_model=PaginatedAttackersResponse, summary="List observed attacker profiles")
def list_attackers(
    data_access: TenantDataAccess = Depends(get_tenant_data_access),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    limit: Optional[int] = Query(None, ge=1, le=100, description="Alias for page_size"),
    min_severity: Optional[str] = Query(None, description="Minimum observed severity"),
    search: Optional[str] = Query(None, description="Search by source IP"),
):
    effective_page_size = limit if limit is not None else page_size
    items, total = data_access.list_attackers(
        page=page,
        page_size=effective_page_size,
        min_severity=min_severity,
        search=search,
    )

    total_pages = ceil(total / effective_page_size) if total > 0 else 1

    return PaginatedAttackersResponse(
        total=total,
        page=page,
        page_size=effective_page_size,
        limit=effective_page_size,
        total_pages=total_pages,
        items=[it.to_dict() for it in items],
    )


@router.get("/attackers/{attacker_id}", response_model=AttackerProfileResponse, summary="Get attacker profile details")
def get_attacker(attacker_id: str, data_access: TenantDataAccess = Depends(get_tenant_data_access)):
    try:
        profile = data_access.get_attacker(attacker_id)
    except CrossTenantAccessDeniedException as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        )

    if not profile:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Attacker profile '{attacker_id}' not found",
        )
    return profile.to_dict()

