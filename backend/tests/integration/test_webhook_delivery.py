"""Integration tests for Webhook Delivery System."""

from datetime import datetime, timezone
import hashlib
import hmac
import json
from unittest.mock import patch, MagicMock
import urllib.error
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.app.core.exceptions import CrossTenantAccessDeniedException
from backend.app.models.asset import DeceptiveAsset
from backend.app.models.event import AttackEvent
from backend.app.models.integration import IntegrationConfig
from backend.app.models.tenant import Tenant
from backend.app.models.webhook_delivery import WebhookDelivery
from backend.app.schemas.webhook import WebhookDeliveryStatus
from backend.app.services.ingestion_service import IngestionService
from backend.app.services.tenant_data_access import TenantDataAccess
from backend.app.services.webhook_service import WebhookDeliveryService, is_ssrf_safe_url


TENANT_A = "tenant-apex-001"
TENANT_B = "tenant-cyber-002"


@pytest.fixture(autouse=True)
def setup_tenants_and_assets(test_db: Session):
    """Seed test tenants and parent deceptive assets."""
    now = datetime.now(timezone.utc)

    # Tenant A
    t1 = test_db.query(Tenant).filter(Tenant.tenant_id == TENANT_A).first()
    if not t1:
        test_db.add(Tenant(tenant_id=TENANT_A, name="Apex Tenant", is_active=True))

    # Tenant B
    t2 = test_db.query(Tenant).filter(Tenant.tenant_id == TENANT_B).first()
    if not t2:
        test_db.add(Tenant(tenant_id=TENANT_B, name="Cyber Tenant", is_active=True))

    # Assets
    a1 = test_db.query(DeceptiveAsset).filter(DeceptiveAsset.asset_id == "ssh-001").first()
    if not a1:
        test_db.add(DeceptiveAsset(
            asset_id="ssh-001",
            tenant_id=TENANT_A,
            name="SSH Asset",
            asset_type="ssh_honeypot",
            environment="production",
            status="active",
        ))

    test_db.commit()


def test_ssrf_protection_blocks_cloud_metadata_and_loopback():
    """Verify SSRF validator blocks cloud metadata, loopback, and private addresses."""
    # 1. AWS / GCP Metadata endpoints
    is_safe_aws, err_aws = is_ssrf_safe_url("http://169.254.169.254/latest/meta-data/")
    assert is_safe_aws is False
    assert "metadata" in err_aws.lower()

    is_safe_gcp, err_gcp = is_ssrf_safe_url("http://metadata.google.internal/computeMetadata/v1/")
    assert is_safe_gcp is False
    assert "metadata" in err_gcp.lower()

    # 2. Localhost / loopback
    is_safe_local, err_local = is_ssrf_safe_url("http://localhost:8080/hook", allow_internal=False)
    assert is_safe_local is False

    is_safe_ip, err_ip = is_ssrf_safe_url("http://127.0.0.1:8000/hook", allow_internal=False)
    assert is_safe_ip is False

    # 3. Legitimate public HTTPS URL
    is_safe_pub, err_pub = is_ssrf_safe_url("https://hooks.slack.com/services/T00/B00/X00")
    assert is_safe_pub is True
    assert err_pub is None


def test_successful_webhook_delivery_with_signature(test_db: Session):
    """Test successful webhook dispatch with HMAC-SHA256 signature verification."""
    now = datetime.now(timezone.utc)
    secret_key = "webhook_secret_key_9999"

    # Setup webhook integration
    intg = IntegrationConfig(
        integration_id="intg-test-wh-01",
        tenant_id=TENANT_A,
        name="Test SecOps Webhook",
        integration_type="webhook",
        enabled=True,
        status="verified",
        config_metadata={
            "url": "https://example.com/secops-hook",
            "events": ["*"],
            "secret": secret_key,
        },
    )
    test_db.add(intg)

    # Setup event
    evt = AttackEvent(
        event_id="evt-signed-001",
        tenant_id=TENANT_A,
        source_ip="198.51.100.25",
        source_service="ssh",
        asset_id="ssh-001",
        event_type="command_execution",
        severity="high",
        status="attempt",
        timestamp=now,
        activity={"command": "cat /etc/passwd"},
    )
    test_db.add(evt)
    test_db.commit()

    captured_req = {}

    def mock_urlopen(req, timeout=None):
        captured_req["url"] = req.full_url
        captured_req["headers"] = dict(req.headers)
        captured_req["data"] = req.data

        resp = MagicMock()
        resp.status = 200
        resp.read.return_value = b'{"success": true}'
        resp.__enter__.return_value = resp
        return resp

    svc = WebhookDeliveryService(test_db)
    with patch("urllib.request.urlopen", side_effect=mock_urlopen):
        deliveries = svc.dispatch_for_event(evt)

    assert len(deliveries) == 1
    d = deliveries[0]
    assert d.status == WebhookDeliveryStatus.DELIVERED.value
    assert d.status_code == 200
    assert d.delivered_at is not None

    # Verify signature
    assert "X-drishti-signature" in captured_req["headers"]
    sig_header = captured_req["headers"]["X-drishti-signature"]
    expected_sig = "sha256=" + hmac.new(secret_key.encode("utf-8"), captured_req["data"], hashlib.sha256).hexdigest()
    assert sig_header == expected_sig

    # Verify payload content
    payload = json.loads(captured_req["data"].decode("utf-8"))
    assert payload["event_id"] == "evt-signed-001"
    assert payload["tenant_id"] == TENANT_A
    assert payload["event_type"] == "command_execution"


def test_webhook_delivery_failure_and_retry_state(test_db: Session):
    """Test webhook delivery failure triggers retry scheduling without dropping the event."""
    now = datetime.now(timezone.utc)

    intg = IntegrationConfig(
        integration_id="intg-test-wh-fail",
        tenant_id=TENANT_A,
        name="Failing Webhook",
        integration_type="webhook",
        enabled=True,
        status="verified",
        config_metadata={"url": "https://example.com/failing-hook"},
    )
    evt = AttackEvent(
        event_id="evt-fail-001",
        tenant_id=TENANT_A,
        source_ip="198.51.100.25",
        source_service="ssh",
        asset_id="ssh-001",
        event_type="login_attempt",
        severity="medium",
        status="attempt",
        timestamp=now,
    )
    test_db.add_all([intg, evt])
    test_db.commit()

    # Simulate HTTP 500 error
    error_resp = urllib.error.HTTPError(
        url="https://example.com/failing-hook",
        code=500,
        msg="Internal Server Error",
        hdrs={},
        fp=MagicMock(read=lambda size: b"Server Crash"),
    )

    svc = WebhookDeliveryService(test_db)
    with patch("urllib.request.urlopen", side_effect=error_resp):
        deliveries = svc.dispatch_for_event(evt)

    assert len(deliveries) == 1
    d = deliveries[0]
    assert d.status == WebhookDeliveryStatus.RETRYING.value
    assert d.status_code == 500
    assert d.attempts == 1
    assert d.next_retry_at is not None
    assert "500" in d.error_message


def test_webhook_subscription_filtering(test_db: Session):
    """Test that webhooks only receive events matching their subscribed event types."""
    now = datetime.now(timezone.utc)

    # Webhook 1 subscribes only to canary_triggered
    intg_canary = IntegrationConfig(
        integration_id="intg-canary-only",
        tenant_id=TENANT_A,
        name="Canary Alerts Only",
        integration_type="webhook",
        enabled=True,
        config_metadata={
            "url": "https://example.com/canary-alerts",
            "events": ["canary_triggered"],
        },
    )
    # Event is login_attempt (should NOT trigger intg_canary)
    evt_login = AttackEvent(
        event_id="evt-filter-login",
        tenant_id=TENANT_A,
        source_ip="198.51.100.25",
        source_service="ssh",
        asset_id="ssh-001",
        event_type="login_attempt",
        severity="low",
        status="attempt",
        timestamp=now,
    )
    test_db.add_all([intg_canary, evt_login])
    test_db.commit()

    svc = WebhookDeliveryService(test_db)
    deliveries = svc.dispatch_for_event(evt_login)
    assert len(deliveries) == 0  # No delivery triggered

    # Event is canary_triggered (should trigger intg_canary)
    evt_canary = AttackEvent(
        event_id="evt-filter-canary",
        tenant_id=TENANT_A,
        source_ip="198.51.100.25",
        source_service="ssh",
        asset_id="ssh-001",
        event_type="canary_triggered",
        severity="critical",
        status="attempt",
        timestamp=now,
    )
    test_db.add(evt_canary)
    test_db.commit()

    with patch("urllib.request.urlopen") as mock_open:
        mock_resp = MagicMock(status=200, read=lambda s: b"ok")
        mock_resp.__enter__.return_value = mock_resp
        mock_open.return_value = mock_resp

        deliveries_canary = svc.dispatch_for_event(evt_canary)

    assert len(deliveries_canary) == 1
    assert deliveries_canary[0].event_type == "canary_triggered"


def test_ingestion_pipeline_continuity_on_webhook_failure(test_db: Session):
    """Verify that webhook delivery failures never interrupt or block event ingestion."""
    # Setup webhook with failing endpoint
    intg = IntegrationConfig(
        integration_id="intg-bomb",
        tenant_id=TENANT_A,
        name="Crash Hook",
        integration_type="webhook",
        enabled=True,
        config_metadata={"url": "https://example.com/bomb"},
    )
    test_db.add(intg)
    test_db.commit()

    raw_event = {
        "event_id": "evt-pipeline-continuity-01",
        "tenant_id": TENANT_A,
        "source_ip": "198.51.100.99",
        "service": "ssh",
        "asset_id": "ssh-001",
        "event_type": "command_execution",
        "command": "uname -a",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    ingestion_service = IngestionService(test_db)

    # Ingest event while webhook endpoint raises connection exception
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")):
        res = ingestion_service.ingest_payload(raw_event)

    # Ingestion MUST succeed regardless of webhook failure
    assert res.status == "success"
    assert res.persisted == 1
    assert len(res.errors) == 0

    # Verify event was persisted in database
    saved_event = test_db.query(AttackEvent).filter(AttackEvent.event_id == "evt-pipeline-continuity-01").first()
    assert saved_event is not None
    assert saved_event.source_ip == "198.51.100.99"


def test_multi_tenant_webhook_isolation(client: TestClient, test_db: Session):
    """Test that webhooks and deliveries are strictly isolated between tenants."""
    now = datetime.now(timezone.utc)

    # Tenant A webhook delivery
    d_a = WebhookDelivery(
        delivery_id="dlv-private-a",
        tenant_id=TENANT_A,
        integration_id="intg-test-wh-01",
        event_id="evt-signed-001",
        destination_url="https://example.com/tenant-a-hook",
        event_type="command_execution",
        severity="high",
        payload={"event_id": "evt-signed-001"},
        status=WebhookDeliveryStatus.DELIVERED.value,
        attempts=1,
    )
    test_db.add(d_a)
    test_db.commit()

    # Tenant B tries to read Tenant A's delivery -> 403 Forbidden
    res_b = client.get("/api/webhooks/deliveries/dlv-private-a", headers={"X-Tenant-ID": TENANT_B})
    assert res_b.status_code == 403
    assert "access denied" in res_b.json()["detail"].lower()

    # Tenant B tries to retry Tenant A's delivery -> 403 Forbidden
    res_retry_b = client.post("/api/webhooks/deliveries/dlv-private-a/retry", headers={"X-Tenant-ID": TENANT_B})
    assert res_retry_b.status_code == 403
    assert "access denied" in res_retry_b.json()["detail"].lower()

    # Direct data-access layer isolation check
    da_b = TenantDataAccess(test_db, TENANT_B)
    with pytest.raises(CrossTenantAccessDeniedException):
        da_b.get_webhook_delivery("dlv-private-a")

    with pytest.raises(CrossTenantAccessDeniedException):
        da_b.retry_webhook_delivery("dlv-private-a")
