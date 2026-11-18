"""Pydantic schemas for Honeytoken Lifecycle Management."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ConfigDict, field_validator


class HoneytokenStatus(str, Enum):
    ACTIVE = "active"
    TRIGGERED = "triggered"
    EXPIRED = "expired"
    REVOKED = "revoked"


class HoneytokenType(str, Enum):
    AWS_IAM = "aws_iam"
    SSH_CREDENTIAL = "ssh_credential"
    DATABASE_CREDENTIAL = "database_credential"
    API_TOKEN = "api_token"
    CUSTOM = "custom"


VALID_HONEYTOKEN_STATUS_TRANSITIONS = {
    HoneytokenStatus.ACTIVE: {HoneytokenStatus.TRIGGERED, HoneytokenStatus.EXPIRED, HoneytokenStatus.REVOKED},
    HoneytokenStatus.TRIGGERED: {HoneytokenStatus.ACTIVE, HoneytokenStatus.REVOKED, HoneytokenStatus.EXPIRED},
    HoneytokenStatus.EXPIRED: {HoneytokenStatus.ACTIVE, HoneytokenStatus.REVOKED},
    HoneytokenStatus.REVOKED: set(),  # Terminal state
}


class HoneytokenBase(BaseModel):
    name: str = Field(..., min_length=2, max_length=128, description="Human-readable token name")
    token_type: str = Field(..., description="Honeytoken classification (aws_iam, ssh_credential, database_credential, api_token)")
    asset_id: str = Field(..., min_length=2, max_length=64, description="Parent deceptive asset ID in registry")
    description: Optional[str] = Field(None, max_length=256, description="Optional description of token planting context")
    status: str = Field(default=HoneytokenStatus.ACTIVE.value, description="Status: active, triggered, expired, revoked")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Safe metadata regarding planting location and hints")
    expires_at: Optional[datetime] = Field(None, description="Optional token expiration timestamp (UTC)")

    @field_validator("name", "token_type", "asset_id", mode="before")
    @classmethod
    def strip_strings(cls, v: Any) -> Any:
        if isinstance(v, str):
            return v.strip()
        return v

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: str) -> str:
        clean = v.strip().lower()
        valid = [s.value for s in HoneytokenStatus]
        if clean not in valid:
            raise ValueError(f"Invalid status '{clean}'. Must be one of {valid}")
        return clean

    @field_validator("metadata")
    @classmethod
    def sanitize_metadata(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        """Ensure no raw passwords or secrets are accidentally logged in metadata."""
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


class HoneytokenCreate(HoneytokenBase):
    token_id: Optional[str] = Field(None, min_length=3, max_length=64, description="Custom token ID or auto-generated")
    tenant_id: Optional[str] = Field(None, max_length=64, description="Tenant ID (defaults to authenticated tenant)")
    token_value: Optional[str] = Field(None, max_length=512, description="Optional initial value for manual token registration")


class HoneytokenGenerateRequest(BaseModel):
    asset_id: str = Field(..., min_length=2, max_length=64, description="Deceptive asset ID where token is planted")
    token_type: str = Field(..., description="Type of fake credential to generate: aws_iam, ssh_credential, database_credential, api_token")
    name: str = Field(..., min_length=2, max_length=128, description="Descriptive label for this honeytoken")
    description: Optional[str] = Field(None, max_length=256, description="Description of decoy placement")
    expires_in_days: Optional[int] = Field(None, ge=1, le=365, description="Optional lifespan in days")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Contextual decoy metadata")

    @field_validator("token_type")
    @classmethod
    def validate_type(cls, v: str) -> str:
        clean = v.strip().lower()
        valid = [t.value for t in HoneytokenType]
        if clean not in valid:
            raise ValueError(f"Invalid token_type '{clean}'. Must be one of {valid}")
        return clean


class HoneytokenResponse(HoneytokenBase):
    model_config = ConfigDict(from_attributes=True)

    token_id: str
    tenant_id: str
    token_value_masked: str
    token_hash: str
    trigger_count: int
    last_triggered_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime


class HoneytokenGeneratedResponse(HoneytokenResponse):
    """Returned ONLY at token generation or initial registration. Plaintext secret is never retrievable again."""
    generated_credentials: Dict[str, Any] = Field(
        ...,
        description="The raw fake credentials generated (e.g. AWS Access Key & Secret Key). Store safely or plant in decoy!"
    )


class HoneytokenUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=128)
    description: Optional[str] = Field(None, max_length=256)
    status: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    expires_at: Optional[datetime] = None

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        clean = v.strip().lower()
        valid = [s.value for s in HoneytokenStatus]
        if clean not in valid:
            raise ValueError(f"Invalid status '{clean}'. Must be one of {valid}")
        return clean


class HoneytokenTriggerRequest(BaseModel):
    trigger_type: str = Field(default="honeytoken_access", description="e.g. token_read, token_auth_attempt, api_invocation")
    source_ip: str = Field(default="127.0.0.1", description="Attacker IP address")
    source_port: Optional[int] = Field(None, ge=1, le=65535, description="Attacker source port")
    source_service: Optional[str] = Field(None, description="Service where token was triggered (ssh, web, ftp, database, cloud)")
    username: Optional[str] = Field(None, description="Username associated with trigger")
    details: Dict[str, Any] = Field(default_factory=dict, description="Trigger context and observation details")


class PaginatedHoneytokensResponse(BaseModel):
    total: int
    page: int
    page_size: int
    limit: int
    total_pages: int
    items: List[HoneytokenResponse]
