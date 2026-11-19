"""Webhook Delivery Tracking and Management API endpoints."""

from math import ceil
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status

from backend.app.api.deps import get_tenant_data_access
from backend.app.core.exceptions import CrossTenantAccessDeniedException
from backend.app.schemas.webhook import (
    WebhookDeliveryResponse,
    PaginatedWebhookDeliveriesResponse,
    WebhookDeliverySummary,
    WebhookRetryResponse,
)
from backend.app.services.tenant_data_access import TenantDataAccess

router = APIRouter()


@router.get(
    "/webhooks/deliveries/summary",
    response_model=WebhookDeliverySummary,
    summary="Get webhook delivery performance metrics and summary for tenant",
)
def get_webhook_summary(
    data_access: TenantDataAccess = Depends(get_tenant_data_access),
):
    summary = data_access.get_webhook_delivery_summary()
    return WebhookDeliverySummary(**summary)


@router.get(
    "/webhooks/deliveries",
    response_model=PaginatedWebhookDeliveriesResponse,
    summary="List webhook notification delivery attempts",
)
def list_webhook_deliveries(
    data_access: TenantDataAccess = Depends(get_tenant_data_access),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    limit: Optional[int] = Query(None, ge=1, le=100, description="Alias for page_size"),
    status: Optional[str] = Query(None, description="Filter by status (pending, delivered, failed, retrying)"),
    integration_id: Optional[str] = Query(None, description="Filter by integration configuration ID"),
    event_id: Optional[str] = Query(None, description="Filter by security attack event ID"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
):
    effective_page_size = limit if limit is not None else page_size
    items, total = data_access.list_webhook_deliveries(
        page=page,
        page_size=effective_page_size,
        status=status,
        integration_id=integration_id,
        event_id=event_id,
        event_type=event_type,
    )

    total_pages = ceil(total / effective_page_size) if total > 0 else 1

    return PaginatedWebhookDeliveriesResponse(
        total=total,
        page=page,
        page_size=effective_page_size,
        limit=effective_page_size,
        total_pages=total_pages,
        items=[it.to_dict() for it in items],
    )


@router.get(
    "/webhooks/deliveries/{delivery_id}",
    response_model=WebhookDeliveryResponse,
    summary="Retrieve details of a specific webhook delivery attempt",
)
def get_webhook_delivery(
    delivery_id: str,
    data_access: TenantDataAccess = Depends(get_tenant_data_access),
):
    try:
        delivery = data_access.get_webhook_delivery(delivery_id)
    except CrossTenantAccessDeniedException as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        )

    if not delivery:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Webhook delivery '{delivery_id}' not found",
        )
    return delivery.to_dict()


@router.post(
    "/webhooks/deliveries/{delivery_id}/retry",
    response_model=WebhookRetryResponse,
    summary="Manually retry a failed webhook delivery attempt",
)
def retry_webhook_delivery(
    delivery_id: str,
    data_access: TenantDataAccess = Depends(get_tenant_data_access),
):
    try:
        delivery = data_access.retry_webhook_delivery(delivery_id)
    except CrossTenantAccessDeniedException as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        )

    if not delivery:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Webhook delivery '{delivery_id}' not found",
        )

    return WebhookRetryResponse(
        delivery_id=delivery.delivery_id,
        status=delivery.status,
        attempts=delivery.attempts,
        message=f"Delivery attempt completed with status: {delivery.status}" + (
            f" (Error: {delivery.error_message})" if delivery.error_message else ""
        ),
    )
