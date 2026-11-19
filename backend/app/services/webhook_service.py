"""Webhook Delivery and Management Service for DRISTHI."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta
import hashlib
import hmac
import ipaddress
import json
import socket
from typing import Any, Dict, List, Optional, Tuple
import urllib.error
import urllib.parse
import urllib.request
import uuid

from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.core.logging import logger
from backend.app.core.security import sanitize_credentials
from backend.app.models.event import AttackEvent
from backend.app.models.integration import IntegrationConfig
from backend.app.models.webhook_delivery import WebhookDelivery
from backend.app.schemas.webhook import WebhookDeliveryStatus

# Thread pool for non-blocking asynchronous webhook delivery
_delivery_executor = ThreadPoolExecutor(max_workers=5, thread_name_prefix="drishti-webhook-worker")

# Cloud metadata addresses and prohibited SSRF targets
BLOCKED_METADATA_HOSTS = {
    "169.254.169.254",
    "metadata.google.internal",
    "100.100.100.200",
    "169.254.170.2",
    "metadata.packet.net",
}


def is_ssrf_safe_url(url: str, allow_internal: bool = False) -> Tuple[bool, Optional[str]]:
    """Validates URL against SSRF vulnerabilities, loopback targets, and cloud metadata services."""
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception as exc:
        return False, f"Invalid URL syntax: {exc}"

    if parsed.scheme.lower() not in ("http", "https"):
        return False, f"Unsupported URL scheme '{parsed.scheme}'. Only http and https are permitted."

    hostname = parsed.hostname
    if not hostname:
        return False, "URL must contain a valid hostname"

    clean_host = hostname.strip().lower()

    # Block well-known cloud metadata endpoints unconditionally
    if clean_host in BLOCKED_METADATA_HOSTS:
        return False, f"Access to cloud metadata service '{clean_host}' is strictly prohibited."

    if allow_internal:
        return True, None

    # Check for localhost / loopback identifiers
    if clean_host in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):
        return False, "Destination URL cannot point to localhost or loopback interfaces."

    # Resolve IP address to detect private / internal network targets (RFC 1918, RFC 3927)
    try:
        resolved_ips = socket.getaddrinfo(clean_host, None)
        for item in resolved_ips:
            ip_str = item[4][0]
            ip_obj = ipaddress.ip_address(ip_str)

            if ip_obj.is_loopback:
                return False, f"Destination resolves to loopback IP '{ip_str}'."
            if ip_obj.is_private:
                return False, f"Destination resolves to private network IP '{ip_str}'."
            if ip_obj.is_link_local:
                return False, f"Destination resolves to link-local IP '{ip_str}'."
            if ip_obj.is_reserved:
                return False, f"Destination resolves to reserved IP '{ip_str}'."
    except socket.gaierror:
        # Host cannot be resolved yet (may be transient DNS in dev/test) - permit or log warning
        pass
    except Exception as exc:
        return False, f"DNS resolution failed: {exc}"

    return True, None


def sign_payload(secret: str, payload_bytes: bytes) -> str:
    """Computes HMAC-SHA256 signature for payload verification by consumers."""
    return hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()


class WebhookDeliveryService:
    """Manages subscription filtering, payload building, SSRF safety, and async delivery."""

    def __init__(self, db: Session):
        self.db = db

    @classmethod
    def matches_subscriptions(cls, config_metadata: Dict[str, Any], event_type: str, severity: str) -> bool:
        """Determines if a security event matches an integration's subscription filter."""
        meta = config_metadata or {}
        subscribed_events = meta.get("events") or meta.get("event_subscriptions") or ["*"]

        # 1. Event type matching
        if "*" not in subscribed_events:
            clean_events = [e.strip().lower() for e in subscribed_events if isinstance(e, str)]
            if event_type.strip().lower() not in clean_events:
                return False

        # 2. Minimum severity matching (optional)
        min_severity = meta.get("min_severity")
        if min_severity:
            sev_levels = ["low", "medium", "high", "critical"]
            min_clean = min_severity.strip().lower()
            if min_clean in sev_levels:
                event_sev = severity.strip().lower()
                if event_sev in sev_levels:
                    if sev_levels.index(event_sev) < sev_levels.index(min_clean):
                        return False

        return True

    @classmethod
    def build_webhook_payload(cls, event: AttackEvent) -> Dict[str, Any]:
        """Constructs safe, structured event notification payload with credentials sanitized."""
        activity = sanitize_credentials(event.activity or {})
        metadata = sanitize_credentials(event.metadata_ or {})

        timestamp_str = (
            event.timestamp.isoformat()
            if hasattr(event.timestamp, "isoformat")
            else str(event.timestamp)
        )

        return {
            "event_id": event.event_id,
            "event_type": event.event_type,
            "timestamp": timestamp_str,
            "tenant_id": event.tenant_id,
            "asset_id": event.asset_id,
            "source_service": event.source_service,
            "source_ip": event.source_ip,
            "severity": event.severity,
            "status": event.status,
            "username": event.username,
            "activity": activity,
            "metadata": metadata,
        }

    def dispatch_for_event(self, event: AttackEvent) -> List[WebhookDelivery]:
        """Identifies matching webhook integrations and executes or schedules delivery attempts."""
        # Find active webhook integrations for this event's tenant
        integrations = self.db.query(IntegrationConfig).filter(
            IntegrationConfig.tenant_id == event.tenant_id,
            IntegrationConfig.integration_type == "webhook",
            IntegrationConfig.enabled.is_(True),
        ).all()

        if not integrations:
            return []

        deliveries = []
        payload_dict = self.build_webhook_payload(event)

        for intg in integrations:
            meta = intg.config_metadata or {}
            dest_url = meta.get("url") or meta.get("endpoint_url")
            if not dest_url:
                continue

            if not self.matches_subscriptions(meta, event.event_type, event.severity):
                continue

            # Duplicate delivery protection: check if delivery already queued/attempted for this event & integration
            existing_delivery = self.db.query(WebhookDelivery).filter(
                WebhookDelivery.event_id == event.event_id,
                WebhookDelivery.integration_id == intg.integration_id,
            ).first()
            if existing_delivery:
                logger.info("Skipping duplicate webhook delivery for event %s to %s", event.event_id, intg.integration_id)
                continue

            delivery_id = f"dlv-{uuid.uuid4().hex[:12]}"
            now = datetime.now(timezone.utc)

            delivery = WebhookDelivery(
                delivery_id=delivery_id,
                tenant_id=event.tenant_id,
                integration_id=intg.integration_id,
                event_id=event.event_id,
                destination_url=dest_url,
                event_type=event.event_type,
                severity=event.severity,
                payload=payload_dict,
                status=WebhookDeliveryStatus.PENDING.value,
                attempts=0,
                max_attempts=settings.WEBHOOK_MAX_RETRIES,
                created_at=now,
                updated_at=now,
            )
            self.db.add(delivery)
            deliveries.append((delivery, intg))

        if deliveries:
            self.db.commit()
            for d, _ in deliveries:
                self.db.refresh(d)

        # Execute deliveries synchronously or in background
        dispatched_models = []
        for delivery, intg in deliveries:
            self._execute_single_delivery(delivery, intg)
            dispatched_models.append(delivery)

        return dispatched_models

    def _execute_single_delivery(self, delivery: WebhookDelivery, integration: IntegrationConfig) -> WebhookDelivery:
        """Executes an HTTP POST delivery to the destination URL with signature and SSRF safety."""
        now = datetime.now(timezone.utc)
        delivery.attempts += 1
        delivery.last_attempt_at = now

        # 1. SSRF Safety Check
        allow_internal = settings.WEBHOOK_ALLOW_INTERNAL_URLS or integration.config_metadata.get("allow_internal", False)
        is_safe, ssrf_error = is_ssrf_safe_url(delivery.destination_url, allow_internal=allow_internal)
        if not is_safe:
            delivery.status = WebhookDeliveryStatus.FAILED.value
            delivery.error_message = f"SSRF Protection blocked delivery: {ssrf_error}"
            delivery.updated_at = now
            self.db.commit()
            logger.warning("Webhook delivery %s blocked by SSRF: %s", delivery.delivery_id, ssrf_error)
            return delivery

        # 2. Serialize Payload & Prepare Headers
        payload_bytes = json.dumps(delivery.payload, separators=(",", ":")).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "DRISTHI-Webhook-Forwarder/1.0",
            "X-Drishti-Event": delivery.event_type,
            "X-Drishti-Delivery": delivery.delivery_id,
            "X-Drishti-Timestamp": now.isoformat(),
        }

        # Include custom headers configured in metadata
        custom_headers = integration.config_metadata.get("headers") or {}
        for hk, hv in custom_headers.items():
            if isinstance(hk, str) and isinstance(hv, str) and not any(s in hk.lower() for s in ["authorization", "secret"]):
                headers[hk] = hv

        # 3. Add HMAC-SHA256 Signature if secret exists
        signing_secret = integration.config_metadata.get("secret") or integration.secret_storage
        if signing_secret:
            signature = sign_payload(signing_secret, payload_bytes)
            headers["X-Drishti-Signature"] = f"sha256={signature}"

        # 4. Dispatch HTTP Request
        req = urllib.request.Request(
            delivery.destination_url,
            data=payload_bytes,
            headers=headers,
            method="POST",
        )

        timeout = settings.WEBHOOK_TIMEOUT_SECONDS
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status_code = resp.status
                body = resp.read(1024).decode("utf-8", errors="replace")

                delivery.status_code = status_code
                delivery.response_body = body
                if 200 <= status_code < 300:
                    delivery.status = WebhookDeliveryStatus.DELIVERED.value
                    delivery.delivered_at = now
                    delivery.error_message = None
                    logger.info("Webhook %s successfully delivered to %s (status %d)", delivery.delivery_id, delivery.destination_url, status_code)
                else:
                    delivery.status = WebhookDeliveryStatus.FAILED.value
                    delivery.error_message = f"HTTP {status_code} response received"
        except urllib.error.HTTPError as exc:
            delivery.status_code = exc.code
            delivery.response_body = exc.read(1024).decode("utf-8", errors="replace")
            delivery.error_message = f"HTTP Error {exc.code}: {exc.reason}"
            if delivery.attempts < delivery.max_attempts:
                delivery.status = WebhookDeliveryStatus.RETRYING.value
                delivery.next_retry_at = now + timedelta(seconds=2 ** delivery.attempts)
            else:
                delivery.status = WebhookDeliveryStatus.FAILED.value
        except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
            delivery.status_code = None
            err_str = str(exc)
            delivery.error_message = f"Connection failed: {err_str[:400]}"
            if delivery.attempts < delivery.max_attempts:
                delivery.status = WebhookDeliveryStatus.RETRYING.value
                delivery.next_retry_at = now + timedelta(seconds=2 ** delivery.attempts)
            else:
                delivery.status = WebhookDeliveryStatus.FAILED.value
        except Exception as exc:
            delivery.status_code = None
            delivery.error_message = f"Unexpected failure: {str(exc)[:400]}"
            delivery.status = WebhookDeliveryStatus.FAILED.value

        delivery.updated_at = now
        self.db.commit()
        self.db.refresh(delivery)
        return delivery

    def retry_delivery(self, delivery_id: str, tenant_id: str) -> Optional[WebhookDelivery]:
        """Manually re-triggers a failed or retrying webhook delivery attempt."""
        delivery = self.db.query(WebhookDelivery).filter(
            WebhookDelivery.delivery_id == delivery_id.strip(),
            WebhookDelivery.tenant_id == tenant_id.strip(),
        ).first()

        if not delivery:
            return None

        integration = self.db.query(IntegrationConfig).filter(
            IntegrationConfig.integration_id == delivery.integration_id,
            IntegrationConfig.tenant_id == tenant_id.strip(),
        ).first()

        if not integration:
            delivery.status = WebhookDeliveryStatus.FAILED.value
            delivery.error_message = "Parent integration configuration was deleted"
            delivery.updated_at = datetime.now(timezone.utc)
            self.db.commit()
            return delivery

        return self._execute_single_delivery(delivery, integration)

    @classmethod
    def dispatch_async(cls, event_dict: Dict[str, Any]):
        """Dispatches webhook deliveries in a background thread so ingestion is never blocked."""
        def _run():
            from backend.app.database.connection import SessionLocal
            db = SessionLocal()
            try:
                event_id = event_dict.get("event_id")
                event = db.query(AttackEvent).filter(AttackEvent.event_id == event_id).first()
                if event:
                    svc = cls(db)
                    svc.dispatch_for_event(event)
            except Exception as exc:
                logger.error("Async webhook dispatch error for event %s: %s", event_dict.get("event_id"), exc)
            finally:
                db.close()

        _delivery_executor.submit(_run)
