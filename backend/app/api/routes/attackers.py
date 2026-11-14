"""Attacker Profile endpoints."""

from math import ceil
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import desc
from sqlalchemy.orm import Session
from backend.app.database.connection import get_db
from backend.app.models.attacker import AttackerProfile
from backend.app.schemas.attacker import PaginatedAttackersResponse, AttackerProfileResponse

router = APIRouter()


@router.get("/attackers", response_model=PaginatedAttackersResponse, summary="List observed attacker profiles")
def list_attackers(
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    min_severity: Optional[str] = Query(None, description="Minimum observed severity"),
    search: Optional[str] = Query(None, description="Search by source IP"),
):
    query = db.query(AttackerProfile)

    if search:
        query = query.filter(AttackerProfile.source_ip.contains(search.strip()))
    if min_severity:
        sev_order = ["low", "medium", "high", "critical"]
        if min_severity.lower() in sev_order:
            target_idx = sev_order.index(min_severity.lower())
            allowed = sev_order[target_idx:]
            query = query.filter(AttackerProfile.highest_severity.in_(allowed))

    query = query.order_by(desc(AttackerProfile.last_seen))

    total = query.count()
    total_pages = ceil(total / page_size) if total > 0 else 1
    offset = (page - 1) * page_size
    items = query.offset(offset).limit(page_size).all()

    return PaginatedAttackersResponse(
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
        items=[it.to_dict() for it in items],
    )


@router.get("/attackers/{attacker_id}", response_model=AttackerProfileResponse, summary="Get attacker profile details")
def get_attacker(attacker_id: str, db: Session = Depends(get_db)):
    profile = db.query(AttackerProfile).filter(AttackerProfile.attacker_id == attacker_id).first()
    if not profile:
        # Try finding by source_ip if attacker_id wasn't found directly
        profile = db.query(AttackerProfile).filter(AttackerProfile.source_ip == attacker_id).first()
    if not profile:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Attacker profile '{attacker_id}' not found",
        )
    return profile.to_dict()

