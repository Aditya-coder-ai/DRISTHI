"""Pydantic schemas for Deployment Registration."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ConfigDict, field_validator


class DeploymentStatus(str, Enum):
    REGISTERED = "registered"
    ACTIVE = "active"
    INACTIVE = "inactive"
    FAILED = "failed"
    DECOMMISSIONED = "decommissioned"


VALID_DEPLOYMENT_STATUS_TRANSITIONS = {
    DeploymentStatus.REGISTERED: {DeploymentStatus.ACTIVE, DeploymentStatus.INACTIVE, DeploymentStatus.FAILED, DeploymentStatus.DECOMMISSIONED},
    DeploymentStatus.ACTIVE: {DeploymentStatus.INACTIVE, DeploymentStatus.FAILED, DeploymentStatus.DECOMMISSIONED},
    DeploymentStatus.INACTIVE: {DeploymentStatus.ACTIVE, DeploymentStatus.FAILED, DeploymentStatus.DECOMMISSIONED},
    DeploymentStatus.FAILED: {DeploymentStatus.ACTIVE, DeploymentStatus.INACTIVE, DeploymentStatus.DECOMMISSIONED},
    DeploymentStatus.DECOMMISSIONED: {DeploymentStatus.ACTIVE},  # Allow reactivation
}


class DeploymentRegisterRequest(BaseModel):
    """Request schema for deployment self-registration."""
    deployment_id: str = Field(..., min_length=3, max_length=64, description="Unique deployment identifier")
    asset_id: str = Field(..., min_length=3, max_length=64, description="Asset ID from the centralized asset registry")
    asset_type: str = Field(..., description="Asset type (ssh_honeypot, ftp_honeypot, http_honeypot, database_honeypot, honeytoken)")
    environment: str = Field(default="production", max_length=32, description="Deployment environment")
    version: Optional[str] = Field(None, max_length=64, description="Deployment version")
    hostname: Optional[str] = Field(None, max_length=128, description="Hostname of the deployed asset")
    ip_address: Optional[str] = Field(None, max_length=45, description="IP address (IPv4 or IPv6)")
    port: Optional[int] = Field(None, ge=1, le=65535, description="Listening port number")
    deploy_metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional deployment metadata")

    @field_validator("deployment_id", "asset_id", "asset_type", "environment", mode="before")
    @classmethod
    def strip_strings(cls, v: Any) -> Any:
        if isinstance(v, str):
            return v.strip()
        return v

    @field_validator("deploy_metadata")
    @classmethod
    def sanitize_metadata(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        """Ensure no raw passwords or secrets are stored in deployment metadata."""
        sanitized = {}
        for key, val in v.items():
            if key.endswith("_redacted") or key.endswith("_length"):
                sanitized[key] = val
            elif any(secret in key.lower() for secret in ["password", "secret", "private_key", "token_secret"]):
                sanitized[f"{key}_redacted"] = True
                if isinstance(val, str):
                    sanitized[f"{key}_length"] = len(val)
            else:
                sanitized[key] = val
        return sanitized


class DeploymentHeartbeatRequest(BaseModel):
    """Request schema for deployment heartbeat."""
    status: Optional[str] = Field(None, description="Current deployment status")
    version: Optional[str] = Field(None, max_length=64, description="Current running version")
    deploy_metadata: Optional[Dict[str, Any]] = Field(None, description="Updated metadata snapshot")

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        clean = v.strip().lower()
        valid = [s.value for s in DeploymentStatus]
        if clean not in valid:
            raise ValueError(f"Invalid status '{clean}'. Must be one of {valid}")
        return clean


class DeploymentUpdate(BaseModel):
    """Request schema for updating deployment details."""
    environment: Optional[str] = Field(None, max_length=32)
    version: Optional[str] = Field(None, max_length=64)
    hostname: Optional[str] = Field(None, max_length=128)
    ip_address: Optional[str] = Field(None, max_length=45)
    port: Optional[int] = Field(None, ge=1, le=65535)
    status: Optional[str] = None
    deploy_metadata: Optional[Dict[str, Any]] = None

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        clean = v.strip().lower()
        valid = [s.value for s in DeploymentStatus]
        if clean not in valid:
            raise ValueError(f"Invalid status '{clean}'. Must be one of {valid}")
        return clean


class DeploymentResponse(BaseModel):
    """Response schema for deployment records."""
    model_config = ConfigDict(from_attributes=True)

    deployment_id: str
    asset_id: str
    tenant_id: str
    asset_type: str
    environment: str
    version: Optional[str] = None
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    port: Optional[int] = None
    status: str
    registered_at: datetime
    last_heartbeat_at: Optional[datetime] = None
    deploy_metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime


class PaginatedDeploymentsResponse(BaseModel):
    total: int
    page: int
    page_size: int
    limit: int
    total_pages: int
    items: List[DeploymentResponse]
