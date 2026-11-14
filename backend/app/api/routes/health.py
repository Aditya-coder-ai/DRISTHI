"""Health Check endpoint."""

from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session
from backend.app.core.config import settings
from backend.app.database.connection import get_db
from backend.app.models.event import AttackEvent
from backend.app.models.session import AttackerSession
from backend.app.schemas.health import HealthResponse

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
def health_check(db: Session = Depends(get_db)):
    """System health check endpoint verifying database connectivity and operational counters."""
    db_status = "connected"
    try:
        total_events = db.query(func.count(AttackEvent.event_id)).scalar() or 0
        active_sessions = db.query(func.count(AttackerSession.session_id)).filter(
            AttackerSession.status.in_(["active", "escalated"])
        ).scalar() or 0
    except Exception:
        db_status = "disconnected"
        total_events = 0
        active_sessions = 0

    return HealthResponse(
        status="healthy" if db_status == "connected" else "degraded",
        version=settings.VERSION,
        database=db_status,
        active_sessions=active_sessions,
        total_events=total_events,
        timestamp=datetime.now(timezone.utc),
    )

