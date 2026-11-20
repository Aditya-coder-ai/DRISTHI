"""Unit tests for Stripe webhook signature verification and secret hygiene."""

import hashlib
import hmac
import json
import logging
import time
import pytest

from backend.app.core.config import BackendSettings, settings
from backend.app.core.exceptions import (
    WebhookConfigurationError,
    WebhookPayloadError,
    WebhookSignatureVerificationError,
)
from backend.app.core.security import (
    get_stripe_webhook_secret,
    verify_stripe_webhook_signature,
)


def _generate_test_signature_header(payload: bytes, secret: str, timestamp: int | None = None) -> str:
    """Generates a valid Stripe v1 HMAC-SHA256 signature header using a test-only secret."""
    ts = int(time.time()) if timestamp is None else timestamp
    signed_payload = f"{ts}.{payload.decode('utf-8')}".encode("utf-8")
    digest = hmac.new(secret.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()
    return f"t={ts},v1={digest}"


@pytest.fixture
def isolated_test_webhook_secret(monkeypatch):
    """Provides a clearly fake, test-only signing secret isolated via monkeypatch."""
    fake_secret = "drishti_unit_test_only_signing_key_isolated_9f8e7d6c"
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", fake_secret)
    monkeypatch.setattr(settings, "STRIPE_WEBHOOK_SECRET", None)
    return fake_secret


def test_valid_stripe_signature_accepted(isolated_test_webhook_secret):
    """Valid HMAC-SHA256 signed webhook payload is accepted and parsed."""
    payload = json.dumps({"id": "evt_test_001", "type": "invoice.paid"}).encode("utf-8")
    sig_header = _generate_test_signature_header(payload, isolated_test_webhook_secret)

    event = verify_stripe_webhook_signature(payload=payload, sig_header=sig_header)

    assert event["id"] == "evt_test_001"
    assert event["type"] == "invoice.paid"


def test_invalid_stripe_signature_rejected(isolated_test_webhook_secret):
    """Tampered signature or tampered payload is rejected."""
    payload = json.dumps({"id": "evt_test_002", "type": "charge.succeeded"}).encode("utf-8")
    bad_sig_header = _generate_test_signature_header(payload, "wrong_test_signing_key")

    with pytest.raises(WebhookSignatureVerificationError):
        verify_stripe_webhook_signature(payload=payload, sig_header=bad_sig_header)

    # Valid signature for original payload must fail if payload is altered
    valid_sig_header = _generate_test_signature_header(payload, isolated_test_webhook_secret)
    tampered_payload = json.dumps({"id": "evt_test_002", "type": "charge.refunded"}).encode("utf-8")
    with pytest.raises(WebhookSignatureVerificationError):
        verify_stripe_webhook_signature(payload=tampered_payload, sig_header=valid_sig_header)


def test_expired_timestamp_rejected(isolated_test_webhook_secret):
    """Webhook signatures older than tolerance window are rejected to prevent replay attacks."""
    payload = json.dumps({"id": "evt_test_003", "type": "customer.updated"}).encode("utf-8")
    stale_ts = int(time.time()) - 600
    sig_header = _generate_test_signature_header(payload, isolated_test_webhook_secret, timestamp=stale_ts)

    with pytest.raises(WebhookSignatureVerificationError):
        verify_stripe_webhook_signature(payload=payload, sig_header=sig_header, tolerance=300)


def test_missing_or_malformed_signature_header_rejected(isolated_test_webhook_secret):
    """Unsigned or malformed Stripe-Signature headers are never accepted."""
    payload = json.dumps({"id": "evt_test_004"}).encode("utf-8")

    with pytest.raises(WebhookSignatureVerificationError):
        verify_stripe_webhook_signature(payload=payload, sig_header=None)

    with pytest.raises(WebhookSignatureVerificationError):
        verify_stripe_webhook_signature(payload=payload, sig_header="")

    with pytest.raises(WebhookSignatureVerificationError):
        verify_stripe_webhook_signature(payload=payload, sig_header="t=notanint,v1=abc")

    with pytest.raises(WebhookSignatureVerificationError):
        verify_stripe_webhook_signature(payload=payload, sig_header="v1=onlysignature")


def test_missing_production_secret_fails_securely(monkeypatch):
    """Missing, empty, or placeholder STRIPE_WEBHOOK_SECRET fails closed."""
    monkeypatch.delenv("STRIPE_WEBHOOK_SECRET", raising=False)
    monkeypatch.setattr(settings, "STRIPE_WEBHOOK_SECRET", None)

    payload = json.dumps({"id": "evt_test_005"}).encode("utf-8")

    with pytest.raises(WebhookConfigurationError):
        get_stripe_webhook_secret()

    with pytest.raises(WebhookConfigurationError):
        verify_stripe_webhook_signature(payload=payload, sig_header="t=123456,v1=deadbeef")

    # Placeholder from .env.example must also fail closed
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "your_stripe_webhook_secret")
    with pytest.raises(WebhookConfigurationError):
        verify_stripe_webhook_signature(payload=payload, sig_header="t=123456,v1=deadbeef")


def test_malformed_webhook_payload_rejected_safely(isolated_test_webhook_secret):
    """Malformed JSON or non-object JSON payloads are rejected safely even with valid signatures."""
    bad_json = b"{not-valid-json"
    sig_header = _generate_test_signature_header(bad_json, isolated_test_webhook_secret)

    with pytest.raises(WebhookPayloadError):
        verify_stripe_webhook_signature(payload=bad_json, sig_header=sig_header)

    list_payload = b"[1, 2, 3]"
    sig_list = _generate_test_signature_header(list_payload, isolated_test_webhook_secret)
    with pytest.raises(WebhookPayloadError):
        verify_stripe_webhook_signature(payload=list_payload, sig_header=sig_list)

    with pytest.raises(WebhookPayloadError):
        verify_stripe_webhook_signature(payload=b"", sig_header=sig_list)


def test_no_secret_leakage_in_logs_or_exceptions(isolated_test_webhook_secret, caplog):
    """Webhook signing secret must never appear in logs or raised exception messages."""
    caplog.set_level(logging.DEBUG)
    payload = json.dumps({"id": "evt_test_006"}).encode("utf-8")

    # 1. Valid path
    valid_sig = _generate_test_signature_header(payload, isolated_test_webhook_secret)
    verify_stripe_webhook_signature(payload=payload, sig_header=valid_sig)

    # 2. Invalid signature path
    with pytest.raises(WebhookSignatureVerificationError) as exc_sig:
        verify_stripe_webhook_signature(payload=payload, sig_header="t=1700000000,v1=0000")
    assert isolated_test_webhook_secret not in str(exc_sig.value)

    # 3. Malformed payload path
    bad_payload = b"{broken"
    bad_sig = _generate_test_signature_header(bad_payload, isolated_test_webhook_secret)
    with pytest.raises(WebhookPayloadError) as exc_payload:
        verify_stripe_webhook_signature(payload=bad_payload, sig_header=bad_sig)
    assert isolated_test_webhook_secret not in str(exc_payload.value)

    # 4. Verify zero occurrences across all captured log records
    combined_logs = "\n".join(rec.getMessage() for rec in caplog.records)
    assert isolated_test_webhook_secret not in combined_logs


def test_default_settings_do_not_hardcode_stripe_secret(monkeypatch):
    """BackendSettings must never supply a hardcoded default STRIPE_WEBHOOK_SECRET."""
    monkeypatch.delenv("STRIPE_WEBHOOK_SECRET", raising=False)
    fresh_settings = BackendSettings(_env_file=None)
    assert fresh_settings.STRIPE_WEBHOOK_SECRET is None
