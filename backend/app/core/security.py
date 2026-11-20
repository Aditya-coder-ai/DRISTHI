"""Security and authentication utilities for DRISTHI Backend."""

import hashlib
import hmac
import json
import os
import time
from typing import Any, Dict, Optional
from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader, HTTPBearer, HTTPAuthorizationCredentials
from backend.app.core.config import settings
from backend.app.core.exceptions import (
    WebhookConfigurationError,
    WebhookPayloadError,
    WebhookSignatureVerificationError,
)
from backend.app.core.logging import logger

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
bearer_scheme = HTTPBearer(auto_error=False)

_STRIPE_SECRET_PLACEHOLDERS = {
    "your_stripe_webhook_secret",
    "changeme",
    "replace_me",
    "placeholder",
}


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

    if not provided_key or not hmac.compare_digest(provided_key, configured_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing service API key",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return True


def get_stripe_webhook_secret() -> str:
    """Loads STRIPE_WEBHOOK_SECRET from environment/settings and fails closed if missing or placeholder.

    Never logs or returns the secret in error messages.
    """
    env_secret = os.getenv("STRIPE_WEBHOOK_SECRET")
    configured = env_secret if env_secret is not None else settings.STRIPE_WEBHOOK_SECRET
    cleaned = configured.strip() if isinstance(configured, str) else ""

    if not cleaned or cleaned.lower() in _STRIPE_SECRET_PLACEHOLDERS:
        logger.error("Stripe webhook signature verification aborted: signing secret is not configured.")
        raise WebhookConfigurationError(
            "Webhook signing secret is not configured.",
            details={"reason": "missing_or_placeholder_secret"},
        )
    return cleaned


def verify_stripe_webhook_signature(
    payload: bytes,
    sig_header: Optional[str],
    webhook_secret: Optional[str] = None,
    tolerance: Optional[int] = None,
) -> Dict[str, Any]:
    """Verifies an incoming Stripe webhook payload using official Stripe signature verification rules.

    - Uses ``stripe.Webhook.construct_event`` when the official Stripe SDK is installed.
    - Otherwise enforces the identical official Stripe HMAC-SHA256 ``t=<ts>,v1=<hex>`` scheme
      with constant-time comparison and timestamp replay tolerance.
    - Fails closed if ``STRIPE_WEBHOOK_SECRET`` is missing, header is absent/invalid,
      signature does not match, timestamp is outside tolerance, or JSON is malformed.
    - Never logs or embeds secret values in exceptions.
    """
    secret = webhook_secret.strip() if isinstance(webhook_secret, str) and webhook_secret.strip() else get_stripe_webhook_secret()
    if secret.lower() in _STRIPE_SECRET_PLACEHOLDERS:
        logger.error("Stripe webhook signature verification aborted: placeholder secret rejected.")
        raise WebhookConfigurationError(
            "Webhook signing secret is not configured.",
            details={"reason": "placeholder_secret"},
        )

    if not isinstance(payload, (bytes, bytearray)) or len(payload) == 0:
        logger.warning("Rejected empty or non-bytes webhook payload.")
        raise WebhookPayloadError("Webhook payload must be a non-empty JSON document.")

    if not sig_header or not isinstance(sig_header, str):
        logger.warning("Rejected webhook request missing Stripe-Signature header.")
        raise WebhookSignatureVerificationError("Missing webhook signature header.")

    effective_tolerance = (
        settings.STRIPE_WEBHOOK_TOLERANCE_SECONDS if tolerance is None else tolerance
    )

    # Prefer official Stripe SDK when installed
    try:
        import stripe  # type: ignore
    except ImportError:
        stripe = None

    if stripe is not None:
        try:
            event = stripe.Webhook.construct_event(
                payload=bytes(payload),
                sig_header=sig_header,
                secret=secret,
                tolerance=effective_tolerance,
            )
            return dict(event)
        except ValueError:
            logger.warning("Rejected malformed JSON webhook payload during Stripe SDK verification.")
            raise WebhookPayloadError("Malformed JSON webhook payload.")
        except Exception:
            logger.warning("Rejected webhook request failing Stripe SDK signature verification.")
            raise WebhookSignatureVerificationError("Invalid webhook signature.")

    # Official Stripe v1 HMAC-SHA256 verification specification (zero extra runtime dependency)
    timestamp_str: Optional[str] = None
    v1_signatures = []
    for part in sig_header.split(","):
        item = part.strip()
        if "=" not in item:
            continue
        k, v = item.split("=", 1)
        k = k.strip()
        v = v.strip()
        if k == "t" and timestamp_str is None:
            timestamp_str = v
        elif k == "v1" and v:
            v1_signatures.append(v)

    if not timestamp_str or not v1_signatures:
        logger.warning("Rejected webhook request with malformed signature header format.")
        raise WebhookSignatureVerificationError("Malformed webhook signature header.")

    try:
        sig_timestamp = int(timestamp_str)
    except ValueError:
        logger.warning("Rejected webhook request with non-integer signature timestamp.")
        raise WebhookSignatureVerificationError("Invalid webhook signature timestamp.")

    if effective_tolerance > 0 and abs(int(time.time()) - sig_timestamp) > effective_tolerance:
        logger.warning("Rejected webhook request with timestamp outside replay tolerance window.")
        raise WebhookSignatureVerificationError("Webhook signature timestamp outside tolerance.")

    try:
        payload_text = bytes(payload).decode("utf-8")
    except UnicodeDecodeError:
        logger.warning("Rejected webhook payload with invalid UTF-8 encoding.")
        raise WebhookPayloadError("Webhook payload is not valid UTF-8.")

    signed_payload = f"{timestamp_str}.{payload_text}".encode("utf-8")
    expected_sig = hmac.new(secret.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()

    if not any(hmac.compare_digest(expected_sig, candidate) for candidate in v1_signatures):
        logger.warning("Rejected webhook request failing HMAC-SHA256 signature verification.")
        raise WebhookSignatureVerificationError("Invalid webhook signature.")

    try:
        parsed = json.loads(payload_text)
    except json.JSONDecodeError:
        logger.warning("Rejected webhook request with malformed JSON payload.")
        raise WebhookPayloadError("Malformed JSON webhook payload.")

    if not isinstance(parsed, dict):
        logger.warning("Rejected webhook payload that is not a JSON object.")
        raise WebhookPayloadError("Webhook payload must be a JSON object.")

    return parsed


def sanitize_credentials(data: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively redacts plaintext passwords, substituting with length or safe flag."""
    sanitized = {}
    for key, value in data.items():
        if isinstance(value, dict):
            sanitized[key] = sanitize_credentials(value)
        elif isinstance(key, str) and (
            any(term in key.lower() for term in ("password", "passwd", "secret", "user_password", "attempted_pass", "creds", "private_key"))
            and not key.lower().endswith(("_length", "_len", "_hash", "_hint"))
        ):
            if isinstance(value, str):
                sanitized["password_length"] = len(value)
            else:
                sanitized["password_provided"] = bool(value)
        else:
            sanitized[key] = value
    return sanitized

