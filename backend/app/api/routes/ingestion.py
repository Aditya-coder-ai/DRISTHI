"""Event Ingestion API endpoints."""

from typing import Any, Dict, List, Union
from fastapi import APIRouter, Depends, status, Request
from backend.app.api.deps import get_ingestion_service
from backend.app.core.security import verify_service_api_key
from backend.app.schemas.event import IngestionResponse
from backend.app.services.ingestion_service import IngestionService

router = APIRouter()


@router.post(
    "/events",
    response_model=IngestionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest deception telemetry events (Person 1 Forwarder contract)",
)
@router.post(
    "/ingestion/events",
    response_model=IngestionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Central Event Ingestion Endpoint",
)
async def ingest_events(
    request: Request,
    ingestion_service: IngestionService = Depends(get_ingestion_service),
    _authorized: bool = Depends(verify_service_api_key),
):
    """Receives, validates, normalizes, and persists deception attack events.
    
    Accepts:
    - Array of Person 1 SecurityEvent objects: `[{ ... }]`
    - Single Person 1 SecurityEvent object: `{ ... }`
    - Platform Normalized Event dictionaries
    """
    payload = await request.json()
    result = ingestion_service.ingest_payload(payload)
    return result

