"""Pydantic schemas for Integration Configuration Registry."""

from datetime import datetime
from enum import Enum
import hashlib
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ConfigDict, field_validator


class IntegrationType(str, Enum):
    WEBHOOK = "webhook"
    SIEM = "siem"
    SECURITY_MONITORING = "security_monitoring"
    CLOUD_INTEGRATION = "cloud_integration"


class IntegrationStatus(str, Enum):
    CONFIGURED = "configured"
    VERIFIED = "verified"
    ERROR = "error"
    DISABLED = "disabled"


def mask_secret(secret_val: str) -> str:
    """Mask sensitive secret strings (e.g., 'hooksec_sample_example_cdef' -> 'hooksec_****_cdef')."""
    clean = secret_val.strip()
    if len(clean) <= 8:
        return "********"
    if "_" in clean[:10]:
        prefix = clean.split("_")[0] + "_"
        suffix = clean[-4:]
        return f"{prefix}****_{suffix}"
    return f"{clean[:4]}****{clean[-4:]}"


def hash_secret(secret_val: str) -> str:
    """Computes SHA-256 fingerprint of the secret."""
    return hashlib.sha256(secret_val.strip().encode("utf-8")).hexdigest()


class IntegrationBase(BaseModel):
    name: str = Field(..., min_length=2, max_length=128, description="Human-readable integration name")
    integration_type: str = Field(..., description="Integration category (webhook, siem, security_monitoring, cloud_integration)")
    config_metadata: Dict[str, Any] = Field(default_factory=dict, description="Integration target configuration")
    enabled: bool = Field(default=True, description="Whether integration is actively enabled")

    @field_validator("name", "integration_type", mode="before")
    @classmethod
    def strip_strings(cls, v: Any) -> Any:
        if isinstance(v, str):
            return v.strip()
        return v

    @field_validator("integration_type")
    @classmethod
    def validate_type(cls, v: str) -> str:
        clean = v.strip().lower()
        valid = [t.value for t in IntegrationType]
        if clean not in valid:
            raise ValueError(f"Invalid integration_type '{clean}'. Must be one of {valid}")
        return clean

    @field_validator("config_metadata")
    @classmethod
    def sanitize_metadata(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        """Ensure no raw passwords or secrets are accidentally saved inside metadata."""
        sanitized = {}
        for key, val in v.items():
            if key.endswith("_redacted") or key.endswith("_length"):
                sanitized[key] = val
            elif any(s in key.lower() for s in ["password", "secret", "private_key", "token_secret", "api_key"]):
                sanitized[f"{key}_redacted"] = True
                if isinstance(val, str):
                    sanitized[f"{key}_length"] = len(val)
            else:
                sanitized[key] = val
        return sanitized


class IntegrationCreate(IntegrationBase):
    integration_id: Optional[str] = Field(None, min_length=3, max_length=64, description="Optional unique integration ID")
    secret: Optional[str] = Field(None, min_length=6, max_length=512, description="Optional secret or API key (masked on retrieval)")

    @field_validator("integration_id", mode="before")
    @classmethod
    def clean_id(cls, v: Any) -> Any:
        if isinstance(v, str):
            clean = v.strip()
            return clean if clean else None
        return v


class IntegrationUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=128)
    config_metadata: Optional[Dict[str, Any]] = None
    enabled: Optional[bool] = None
    status: Optional[str] = None
    secret: Optional[str] = Field(None, min_length=6, max_length=512, description="Rotate/update secret")
    revoke_secret: Optional[bool] = Field(False, description="Set True to revoke existing secret without replacement")

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        clean = v.strip().lower()
        valid = [s.value for s in IntegrationStatus]
        if clean not in valid:
            raise ValueError(f"Invalid status '{clean}'. Must be one of {valid}")
        return clean

    @field_validator("config_metadata")
    @classmethod
    def sanitize_metadata(cls, v: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if v is None:
            return None
        sanitized = {}
        for key, val in v.items():
            if key.endswith("_redacted") or key.endswith("_length"):
                sanitized[key] = val
            elif any(s in key.lower() for s in ["password", "secret", "private_key", "token_secret", "api_key"]):
                sanitized[f"{key}_redacted"] = True
                if isinstance(val, str):
                    sanitized[f"{key}_length"] = len(val)
            else:
                sanitized[key] = val
        return sanitized


class IntegrationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    integration_id: str
    tenant_id: str
    name: str
    integration_type: str
    enabled: bool
    status: str
    config_metadata: Dict[str, Any] = Field(default_factory=dict)
    has_secret: bool = False
    secret_masked: Optional[str] = None
    last_validated_at: Optional[datetime] = None
    validation_details: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime


class PaginatedIntegrationsResponse(BaseModel):
    total: int
    page: int
    page_size: int
    limit: int
    total_pages: int
    items: List[IntegrationResponse]


class IntegrationValidationResult(BaseModel):
    integration_id: str
    is_valid: bool
    status: str
    details: Dict[str, Any]
    validated_at: datetime
