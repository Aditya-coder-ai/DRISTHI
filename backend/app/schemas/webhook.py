"""Pydantic schemas for Webhook Delivery and Management."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class WebhookDeliveryStatus(str, Enum):
    PENDING = "pending"
    DELIVERED = "delivered"
    FAILED = "failed"
    RETRYING = "retrying"


class WebhookPayload(BaseModel):
    """Structured event notification payload delivered to webhook subscribers."""
    event_id: str
    event_type: str
    timestamp: str
    tenant_id: str
    asset_id: str
    source_service: str
    source_ip: str
    severity: str
    status: str
    username: Optional[str] = None
    activity: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class WebhookDeliveryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    delivery_id: str
    tenant_id: str
    integration_id: str
    event_id: str
    destination_url: str
    event_type: str
    severity: str
    payload: Dict[str, Any] = Field(default_factory=dict)
    status: str
    status_code: Optional[int] = None
    response_body: Optional[str] = None
    attempts: int
    max_attempts: int
    last_attempt_at: Optional[datetime] = None
    next_retry_at: Optional[datetime] = None
    delivered_at: Optional[datetime] = None
    error_message: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class PaginatedWebhookDeliveriesResponse(BaseModel):
    total: int
    page: int
    page_size: int
    limit: int
    total_pages: int
    items: List[WebhookDeliveryResponse]


class WebhookDeliverySummary(BaseModel):
    total: int
    delivered: int
    failed: int
    pending: int
    retrying: int
    success_rate: float


class WebhookRetryResponse(BaseModel):
    delivery_id: str
    status: str
    attempts: int
    message: str
