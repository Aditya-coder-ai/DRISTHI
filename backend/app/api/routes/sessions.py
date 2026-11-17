"""Attacker Sessions endpoints."""

from math import ceil
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from backend.app.api.deps import get_tenant_data_access
from backend.app.core.exceptions import CrossTenantAccessDeniedException
from backend.app.schemas.session import PaginatedSessionsResponse, AttackerSessionResponse
from backend.app.services.tenant_data_access import TenantDataAccess

router = APIRouter()


@router.get("/sessions", response_model=PaginatedSessionsResponse, summary="List attacker interaction sessions")
def list_sessions(
    data_access: TenantDataAccess = Depends(get_tenant_data_access),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    limit: Optional[int] = Query(None, ge=1, le=100, description="Alias for page_size"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by session status (active, idle, closed, escalated)"),
    source_ip: Optional[str] = Query(None, description="Filter by attacker source IP"),
):
    effective_page_size = limit if limit is not None else page_size
    items, total = data_access.list_sessions(
        page=page,
        page_size=effective_page_size,
        status_filter=status_filter,
        source_ip=source_ip,
    )

    total_pages = ceil(total / effective_page_size) if total > 0 else 1

    return PaginatedSessionsResponse(
        total=total,
        page=page,
        page_size=effective_page_size,
        limit=effective_page_size,
        total_pages=total_pages,
        items=[it.to_dict() for it in items],
    )


@router.get("/sessions/{session_id}", response_model=AttackerSessionResponse, summary="Get session details")
def get_session(session_id: str, data_access: TenantDataAccess = Depends(get_tenant_data_access)):
    try:
        session = data_access.get_session(session_id)
    except CrossTenantAccessDeniedException as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        )

    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session with ID '{session_id}' not found",
        )
    return session.to_dict()

