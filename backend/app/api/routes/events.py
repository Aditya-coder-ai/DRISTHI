"""Attack Events query endpoints."""

from datetime import datetime
from math import ceil
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import desc, asc
from sqlalchemy.orm import Session
from backend.app.database.connection import get_db
from backend.app.models.event import AttackEvent
from backend.app.schemas.event import PaginatedEventsResponse, AttackEventResponse

router = APIRouter()


@router.get("/events", response_model=PaginatedEventsResponse, summary="Query and filter attack telemetry events")
def list_events(
    db: Session = Depends(get_db),
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
    query = db.query(AttackEvent)

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

    # Sorting
    if order_by == "timestamp_asc":
        query = query.order_by(asc(AttackEvent.timestamp))
    elif order_by == "severity_desc":
        query = query.order_by(desc(AttackEvent.severity), desc(AttackEvent.timestamp))
    else:
        query = query.order_by(desc(AttackEvent.timestamp))

    effective_page_size = limit if limit is not None else page_size
    total = query.count()
    total_pages = ceil(total / effective_page_size) if total > 0 else 1
    offset = (page - 1) * effective_page_size
    items = query.offset(offset).limit(effective_page_size).all()

    return PaginatedEventsResponse(
        total=total,
        page=page,
        page_size=effective_page_size,
        limit=effective_page_size,
        total_pages=total_pages,
        items=[it.to_dict() for it in items],
    )


@router.get("/events/{event_id}", response_model=AttackEventResponse, summary="Retrieve a specific attack event by ID")
def get_event_by_id(event_id: str, db: Session = Depends(get_db)):
    event = db.query(AttackEvent).filter(AttackEvent.event_id == event_id).first()
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Attack event with ID '{event_id}' not found",
        )
    return event.to_dict()

