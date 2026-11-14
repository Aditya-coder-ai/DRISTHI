"""Security and authentication utilities for DRISTHI Backend."""

from typing import Any, Dict, Optional
from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader, HTTPBearer, HTTPAuthorizationCredentials
from backend.app.core.config import settings

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
bearer_scheme = HTTPBearer(auto_error=False)


def verify_service_api_key(
    header_key: Optional[str] = Security(api_key_header),
    bearer_token: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
) -> bool:
    """Verifies that the incoming request is authenticated with the configured BACKEND_API_KEY.
    
    If BACKEND_API_KEY is not configured or empty, requests are permitted (open for local dev/testing).
    If BACKEND_API_KEY is set, one of X-API-Key or Bearer token must match.
    """
    configured_key = settings.BACKEND_API_KEY
    if not configured_key:
        return True

    provided_key = None
    if header_key:
        provided_key = header_key.strip()
    elif bearer_token and bearer_token.credentials:
        provided_key = bearer_token.credentials.strip()

    if not provided_key or provided_key != configured_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing service API key",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return True


def sanitize_credentials(data: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively redacts plaintext passwords, substituting with length or safe flag."""
    sanitized = {}
    for key, value in data.items():
        if isinstance(value, dict):
            sanitized[key] = sanitize_credentials(value)
        elif isinstance(key, str) and key.lower() in ("password", "passwd", "secret", "user_password"):
            if isinstance(value, str):
                sanitized["password_length"] = len(value)
            else:
                sanitized["password_provided"] = bool(value)
        else:
            sanitized[key] = value
    return sanitized

