"""Domain exceptions for DRISTHI Central Backend."""

from typing import Any, Dict, Optional


class DrishtiException(Exception):
    """Base exception for all domain errors."""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class DuplicateEventException(DrishtiException):
    """Raised when an event with the same event_id is submitted."""
    pass


class InvalidPayloadException(DrishtiException):
    """Raised when an incoming event payload fails validation."""
    pass


class AuthenticationException(DrishtiException):
    """Raised when service authentication fails."""
    pass


class ResourceNotFoundException(DrishtiException):
    """Raised when an entity is not found in database."""
    pass


class CrossTenantAccessDeniedException(DrishtiException):
    """Raised when an operation attempts to access or manipulate data across tenant boundaries."""
    pass


class WebhookConfigurationError(DrishtiException):
    """Raised when required webhook signing secret configuration is missing or invalid."""
    pass


class WebhookSignatureVerificationError(DrishtiException):
    """Raised when an incoming webhook signature fails cryptographic or replay verification."""
    pass


class WebhookPayloadError(DrishtiException):
    """Raised when an incoming webhook payload is malformed or invalid JSON."""
    pass

