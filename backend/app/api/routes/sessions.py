"""Attacker Sessions endpoints."""

from math import ceil
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import desc
from sqlalchemy.orm import Session
from backend.app.database.connection import get_db
from backend.app.models.session import AttackerSession
from backend.app.schemas.session import PaginatedSessionsResponse, AttackerSessionResponse

router = APIRouter()


@router.get("/sessions", response_model=PaginatedSessionsResponse, summary="List attacker interaction sessions")
def list_sessions(
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by session status (active, idle, closed, escalated)"),
    source_ip: Optional[str] = Query(None, description="Filter by attacker source IP"),
):
    query = db.query(AttackerSession)

    if status_filter:
        query = query.filter(AttackerSession.status == status_filter.lower())
    if source_ip:
        query = query.filter(AttackerSession.source_ip == source_ip.strip())

    query = query.order_by(desc(AttackerSession.last_seen))

    total = query.count()
    total_pages = ceil(total / page_size) if total > 0 else 1
    offset = (page - 1) * page_size
    items = query.offset(offset).limit(page_size).all()

    return PaginatedSessionsResponse(
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
        items=[it.to_dict() for it in items],
    )


@router.get("/sessions/{session_id}", response_model=AttackerSessionResponse, summary="Get session details")
def get_session(session_id: str, db: Session = Depends(get_db)):
    session = db.query(AttackerSession).filter(AttackerSession.session_id == session_id).first()
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session with ID '{session_id}' not found",
        )
    return session.to_dict()

