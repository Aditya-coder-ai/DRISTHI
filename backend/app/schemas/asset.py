"""Pydantic schemas for Deceptive Asset Registry."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ConfigDict, field_validator


class AssetStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    DECOMMISSIONED = "decommissioned"


class AssetType(str, Enum):
    SSH_HONEYPOT = "ssh_honeypot"
    FTP_HONEYPOT = "ftp_honeypot"
    HTTP_HONEYPOT = "http_honeypot"
    DATABASE_HONEYPOT = "database_honeypot"
    HONEYTOKEN = "honeytoken"
    API_KEY = "api_key"
    CLOUD_CREDENTIAL = "cloud_credential"
    DECOY_FILE = "decoy_file"
    SERVICE_ENDPOINT = "service_endpoint"


# Allowed state transitions: Decommissioned is terminal (cannot transition directly to active without recreation/reactivation policy)
VALID_STATUS_TRANSITIONS = {
    AssetStatus.ACTIVE: {AssetStatus.INACTIVE, AssetStatus.SUSPENDED, AssetStatus.DECOMMISSIONED},
    AssetStatus.INACTIVE: {AssetStatus.ACTIVE, AssetStatus.SUSPENDED, AssetStatus.DECOMMISSIONED},
    AssetStatus.SUSPENDED: {AssetStatus.ACTIVE, AssetStatus.INACTIVE, AssetStatus.DECOMMISSIONED},
    AssetStatus.DECOMMISSIONED: {AssetStatus.ACTIVE},  # Allowed explicit reactivation with audit
}


class AssetBase(BaseModel):
    name: str = Field(..., min_length=2, max_length=128, description="Human-readable asset name")
    asset_type: str = Field(..., description="Asset classification (e.g., ssh_honeypot, honeytoken, api_key)")
    description: Optional[str] = Field(None, max_length=256, description="Optional asset description")
    deployment_id: Optional[str] = Field(None, max_length=64, description="Deployment target/container identifier")
    environment: str = Field(default="production", max_length=32, description="Deployment environment (production, staging, edge)")
    status: str = Field(default=AssetStatus.ACTIVE.value, description="Lifecycle status: active, inactive, suspended, decommissioned")
    config_metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary safe configuration metadata")

    @field_validator("name", "asset_type", "environment", mode="before")
    @classmethod
    def strip_strings(cls, v: Any) -> Any:
        if isinstance(v, str):
            return v.strip()
        return v

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: str) -> str:
        clean = v.strip().lower()
        valid_statuses = [s.value for s in AssetStatus]
        if clean not in valid_statuses:
            raise ValueError(f"Invalid status '{clean}'. Must be one of {valid_statuses}")
        return clean

    @field_validator("config_metadata")
    @classmethod
    def sanitize_metadata(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        """Ensure no raw passwords or secrets are stored in metadata."""
        sanitized = {}
        for key, val in v.items():
            if key.endswith("_redacted") or key.endswith("_length"):
                sanitized[key] = val
            elif any(secret_word in key.lower() for secret_word in ["password", "secret", "private_key", "token_secret"]):
                sanitized[f"{key}_redacted"] = True
                if isinstance(val, str):
                    sanitized[f"{key}_length"] = len(val)
            else:
                sanitized[key] = val
        return sanitized


class AssetCreate(AssetBase):
    asset_id: str = Field(..., min_length=3, max_length=64, description="Unique, stable asset identifier (e.g., ssh-001)")
    tenant_id: Optional[str] = Field(None, max_length=64, description="Tenant ID (defaults to authenticated tenant)")

    @field_validator("asset_id", mode="before")
    @classmethod
    def clean_asset_id(cls, v: Any) -> Any:
        if isinstance(v, str):
            clean = v.strip()
            if not clean:
                raise ValueError("asset_id cannot be empty")
            return clean
        return v


class AssetUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=128)
    description: Optional[str] = Field(None, max_length=256)
    deployment_id: Optional[str] = Field(None, max_length=64)
    environment: Optional[str] = Field(None, max_length=32)
    status: Optional[str] = None
    config_metadata: Optional[Dict[str, Any]] = None

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        clean = v.strip().lower()
        valid_statuses = [s.value for s in AssetStatus]
        if clean not in valid_statuses:
            raise ValueError(f"Invalid status '{clean}'. Must be one of {valid_statuses}")
        return clean


class AssetResponse(AssetBase):
    model_config = ConfigDict(from_attributes=True)

    asset_id: str
    tenant_id: str
    created_at: datetime
    updated_at: datetime


class PaginatedAssetsResponse(BaseModel):
    total: int
    page: int
    page_size: int
    limit: int
    total_pages: int
    items: List[AssetResponse]
