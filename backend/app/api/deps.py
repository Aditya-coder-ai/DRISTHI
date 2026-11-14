"""FastAPI Dependency Injection helpers."""

from typing import Generator
from fastapi import Depends
from sqlalchemy.orm import Session
from backend.app.database.connection import get_db
from backend.app.services.analytics_service import AnalyticsService
from backend.app.services.attacker_service import AttackerService
from backend.app.services.ingestion_service import IngestionService
from backend.app.services.session_service import SessionService


def get_ingestion_service(db: Session = Depends(get_db)) -> IngestionService:
    return IngestionService(db)


def get_analytics_service(db: Session = Depends(get_db)) -> AnalyticsService:
    return AnalyticsService(db)


def get_session_service(db: Session = Depends(get_db)) -> SessionService:
    return SessionService(db)


def get_attacker_service(db: Session = Depends(get_db)) -> AttackerService:
    return AttackerService(db)

