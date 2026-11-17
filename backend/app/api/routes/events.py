"""Attack Events query endpoints."""

from datetime import datetime
from math import ceil
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from backend.app.api.deps import get_tenant_data_access
from backend.app.core.exceptions import CrossTenantAccessDeniedException
from backend.app.schemas.event import PaginatedEventsResponse, AttackEventResponse
from backend.app.services.tenant_data_access import TenantDataAccess

router = APIRouter()


@router.get("/events", response_model=PaginatedEventsResponse, summary="Query and filter attack telemetry events")
def list_events(
    data_access: TenantDataAccess = Depends(get_tenant_data_access),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=200, description="Items per page"),
    limit: Optional[int] = Query(None, ge=1, le=200, description="Alias for page_size"),
    service: Optional[str] = Query(None, description="Filter by decoy service (ssh, ftp, web, database)"),
    severity: Optional[str] = Query(None, description="Filter by severity (low, medium, high, critical)"),
    event_type: Optional[str] = Query(None, description="Filter by event classification"),
    source_ip: Optional[str] = Query(None, description="Filter by attacker source IP"),
    username: Optional[str] = Query(None, description="Filter by username attempted"),
    start_time: Optional[datetime] = Query(None, description="Start time filter (UTC)"),
    end_time: Optional[datetime] = Query(None, description="End time filter (UTC)"),
    order_by: str = Query("timestamp_desc", description="Sort order: timestamp_desc, timestamp_asc, severity_desc"),
):
    effective_page_size = limit if limit is not None else page_size
    items, total = data_access.list_events(
        page=page,
        page_size=effective_page_size,
        service=service,
        severity=severity,
        event_type=event_type,
        source_ip=source_ip,
        username=username,
        start_time=start_time,
        end_time=end_time,
        order_by=order_by,
    )

    total_pages = ceil(total / effective_page_size) if total > 0 else 1

    return PaginatedEventsResponse(
        total=total,
        page=page,
        page_size=effective_page_size,
        limit=effective_page_size,
        total_pages=total_pages,
        items=[it.to_dict() for it in items],
    )


@router.get("/events/{event_id}", response_model=AttackEventResponse, summary="Retrieve a specific attack event by ID")
def get_event_by_id(event_id: str, data_access: TenantDataAccess = Depends(get_tenant_data_access)):
    try:
        event = data_access.get_event(event_id)
    except CrossTenantAccessDeniedException as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        )

    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Attack event with ID '{event_id}' not found",
        )
    return event.to_dict()

