"""Honeytoken Lifecycle Management API endpoints."""

from math import ceil
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status

from backend.app.api.deps import get_tenant_data_access, get_honeytoken_service
from backend.app.core.exceptions import CrossTenantAccessDeniedException
from backend.app.schemas.honeytoken import (
    HoneytokenCreate,
    HoneytokenGenerateRequest,
    HoneytokenGeneratedResponse,
    HoneytokenResponse,
    HoneytokenUpdate,
    HoneytokenTriggerRequest,
    PaginatedHoneytokensResponse,
)
from backend.app.services.honeytoken_service import HoneytokenService
from backend.app.services.tenant_data_access import TenantDataAccess

router = APIRouter()


@router.post(
    "/honeytokens",
    response_model=HoneytokenGeneratedResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new honeytoken (manual or auto-generated value)",
)
def register_honeytoken(
    payload: HoneytokenCreate,
    service: HoneytokenService = Depends(get_honeytoken_service),
):
    try:
        token, raw_creds = service.register_honeytoken(payload)
        token_dict = token.to_dict()
        token_dict["generated_credentials"] = raw_creds or {"token_value": token.token_value_masked}
        return token_dict
    except CrossTenantAccessDeniedException as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.post(
    "/honeytokens/generate",
    response_model=HoneytokenGeneratedResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generate believable fake honeytoken credentials",
)
def generate_honeytoken(
    request: HoneytokenGenerateRequest,
    service: HoneytokenService = Depends(get_honeytoken_service),
):
    try:
        token, raw_creds = service.generate_honeytoken(request)
        token_dict = token.to_dict()
        token_dict["generated_credentials"] = raw_creds
        return token_dict
    except CrossTenantAccessDeniedException as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.get(
    "/honeytokens",
    response_model=PaginatedHoneytokensResponse,
    summary="List registered honeytokens (secrets masked)",
)
def list_honeytokens(
    data_access: TenantDataAccess = Depends(get_tenant_data_access),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    limit: Optional[int] = Query(None, ge=1, le=100, description="Alias for page_size"),
    asset_id: Optional[str] = Query(None, description="Filter by parent deceptive asset ID"),
    token_type: Optional[str] = Query(None, description="Filter by token type (aws_iam, ssh_credential, database_credential, api_token)"),
    status: Optional[str] = Query(None, description="Filter by status (active, triggered, expired, revoked)"),
):
    effective_page_size = limit if limit is not None else page_size
    items, total = data_access.list_honeytokens(
        page=page,
        page_size=effective_page_size,
        asset_id=asset_id,
        token_type=token_type,
        status=status,
    )

    total_pages = ceil(total / effective_page_size) if total > 0 else 1

    return PaginatedHoneytokensResponse(
        total=total,
        page=page,
        page_size=effective_page_size,
        limit=effective_page_size,
        total_pages=total_pages,
        items=[it.to_dict() for it in items],
    )


@router.get(
    "/honeytokens/{token_id}",
    response_model=HoneytokenResponse,
    summary="Get honeytoken details (secret masked)",
)
def get_honeytoken(
    token_id: str,
    data_access: TenantDataAccess = Depends(get_tenant_data_access),
):
    try:
        token = data_access.get_honeytoken(token_id)
        if not token:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Honeytoken '{token_id}' not found",
            )
        return token.to_dict()
    except CrossTenantAccessDeniedException as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))


@router.put(
    "/honeytokens/{token_id}",
    response_model=HoneytokenResponse,
    summary="Update honeytoken details, metadata, or status",
)
def update_honeytoken(
    token_id: str,
    payload: HoneytokenUpdate,
    data_access: TenantDataAccess = Depends(get_tenant_data_access),
):
    try:
        token = data_access.update_honeytoken(token_id, payload)
        if not token:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Honeytoken '{token_id}' not found",
            )
        return token.to_dict()
    except CrossTenantAccessDeniedException as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.post(
    "/honeytokens/{token_id}/rotate",
    response_model=HoneytokenGeneratedResponse,
    summary="Rotate an existing honeytoken (revokes current, generates new replacement)",
)
def rotate_honeytoken(
    token_id: str,
    service: HoneytokenService = Depends(get_honeytoken_service),
):
    try:
        old_token, new_token, raw_creds = service.rotate_honeytoken(token_id)
        token_dict = new_token.to_dict()
        token_dict["generated_credentials"] = raw_creds
        return token_dict
    except CrossTenantAccessDeniedException as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.post(
    "/honeytokens/{token_id}/revoke",
    response_model=HoneytokenResponse,
    summary="Revoke a honeytoken",
)
def revoke_honeytoken(
    token_id: str,
    service: HoneytokenService = Depends(get_honeytoken_service),
):
    try:
        token = service.revoke_honeytoken(token_id)
        return token.to_dict()
    except CrossTenantAccessDeniedException as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.post(
    "/honeytokens/{token_id}/trigger",
    summary="Record or simulate a honeytoken trigger and dispatch to central event pipeline",
)
def trigger_honeytoken(
    token_id: str,
    request: HoneytokenTriggerRequest,
    service: HoneytokenService = Depends(get_honeytoken_service),
):
    try:
        token, raw_event = service.trigger_honeytoken(token_id, request)
        return {
            "status": "triggered",
            "token": token.to_dict(),
            "pipeline_event": {
                "event_id": raw_event["event_id"],
                "tenant_id": raw_event["tenant_id"],
                "asset_id": raw_event["asset_id"],
                "severity": raw_event["severity"],
                "event_type": raw_event["event_type"],
            },
        }
    except CrossTenantAccessDeniedException as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.delete(
    "/honeytokens/{token_id}",
    summary="Revoke or permanently delete a honeytoken",
)
def delete_honeytoken(
    token_id: str,
    hard: bool = Query(False, description="Whether to permanently remove or soft-revoke"),
    data_access: TenantDataAccess = Depends(get_tenant_data_access),
):
    try:
        success = data_access.delete_honeytoken(token_id, hard_delete=hard)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Honeytoken '{token_id}' not found",
            )
        return {
            "status": "success",
            "token_id": token_id,
            "action": "deleted" if hard else "revoked",
        }
    except CrossTenantAccessDeniedException as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
