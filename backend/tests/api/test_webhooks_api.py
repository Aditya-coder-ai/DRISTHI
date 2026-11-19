"""API tests for Webhook Delivery Management."""

from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.app.models.asset import DeceptiveAsset
from backend.app.models.event import AttackEvent
from backend.app.models.integration import IntegrationConfig
from backend.app.models.tenant import Tenant
from backend.app.models.webhook_delivery import WebhookDelivery
from backend.app.schemas.webhook import WebhookDeliveryStatus


@pytest.fixture(autouse=True)
def setup_webhook_test_data(test_db: Session):
    """Seed test data for webhook deliveries."""
    now = datetime.now(timezone.utc)

    # Tenant
    t = test_db.query(Tenant).filter(Tenant.tenant_id == "tenant-apex-001").first()
    if not t:
        test_db.add(Tenant(tenant_id="tenant-apex-001", name="Apex Tenant", is_active=True))

    # Asset
    a = test_db.query(DeceptiveAsset).filter(DeceptiveAsset.asset_id == "ssh-001").first()
    if not a:
        test_db.add(DeceptiveAsset(
            asset_id="ssh-001",
            tenant_id="tenant-apex-001",
            name="SSH Asset",
            asset_type="ssh_honeypot",
            environment="production",
            status="active",
        ))

    # Integration
    intg = test_db.query(IntegrationConfig).filter(IntegrationConfig.integration_id == "intg-wh-test").first()
    if not intg:
        test_db.add(IntegrationConfig(
            integration_id="intg-wh-test",
            tenant_id="tenant-apex-001",
            name="Test Hook",
            integration_type="webhook",
            enabled=True,
            status="verified",
            config_metadata={"url": "https://example.com/test-hook"},
        ))

    # Event
    evt = test_db.query(AttackEvent).filter(AttackEvent.event_id == "evt-wh-test-01").first()
    if not evt:
        test_db.add(AttackEvent(
            event_id="evt-wh-test-01",
            tenant_id="tenant-apex-001",
            source_ip="198.51.100.25",
            source_service="ssh",
            asset_id="ssh-001",
            event_type="command_execution",
            severity="high",
            status="attempt",
            timestamp=now,
        ))

    # Webhook deliveries
    d1 = WebhookDelivery(
        delivery_id="dlv-test-success",
        tenant_id="tenant-apex-001",
        integration_id="intg-wh-test",
        event_id="evt-wh-test-01",
        destination_url="https://example.com/test-hook",
        event_type="command_execution",
        severity="high",
        payload={"event_id": "evt-wh-test-01", "event_type": "command_execution"},
        status=WebhookDeliveryStatus.DELIVERED.value,
        status_code=200,
        response_body='{"ok": true}',
        attempts=1,
        max_attempts=3,
        delivered_at=now,
    )
    d2 = WebhookDelivery(
        delivery_id="dlv-test-failed",
        tenant_id="tenant-apex-001",
        integration_id="intg-wh-test",
        event_id="evt-wh-test-01",
        destination_url="https://example.com/test-hook",
        event_type="command_execution",
        severity="high",
        payload={"event_id": "evt-wh-test-01", "event_type": "command_execution"},
        status=WebhookDeliveryStatus.FAILED.value,
        status_code=500,
        response_body="Internal Server Error",
        attempts=3,
        max_attempts=3,
        error_message="HTTP Error 500",
    )
    test_db.add_all([d1, d2])
    test_db.commit()


def test_list_webhook_deliveries(client: TestClient):
    """Test listing webhook deliveries with pagination and status filters."""
    res = client.get("/api/webhooks/deliveries")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] >= 2
    assert len(data["items"]) >= 2

    # Filter by status: delivered
    res_deliv = client.get("/api/webhooks/deliveries?status=delivered")
    assert res_deliv.status_code == 200
    items = res_deliv.json()["items"]
    assert all(it["status"] == "delivered" for it in items)

    # Filter by status: failed
    res_failed = client.get("/api/webhooks/deliveries?status=failed")
    assert res_failed.status_code == 200
    items_f = res_failed.json()["items"]
    assert all(it["status"] == "failed" for it in items_f)


def test_get_webhook_delivery_summary(client: TestClient):
    """Test retrieving delivery performance summary metrics."""
    res = client.get("/api/webhooks/deliveries/summary")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] >= 2
    assert data["delivered"] >= 1
    assert data["failed"] >= 1
    assert "success_rate" in data
    assert 0.0 <= data["success_rate"] <= 100.0


def test_get_webhook_delivery_by_id(client: TestClient):
    """Test retrieving specific delivery details."""
    res = client.get("/api/webhooks/deliveries/dlv-test-success")
    assert res.status_code == 200
    data = res.json()
    assert data["delivery_id"] == "dlv-test-success"
    assert data["status"] == "delivered"
    assert data["status_code"] == 200
    assert data["payload"]["event_id"] == "evt-wh-test-01"

    # Non-existent delivery
    res_404 = client.get("/api/webhooks/deliveries/dlv-non-existent")
    assert res_404.status_code == 404


def test_retry_webhook_delivery(client: TestClient):
    """Test retrying a failed webhook delivery attempt."""
    res = client.post("/api/webhooks/deliveries/dlv-test-failed/retry")
    assert res.status_code == 200
    data = res.json()
    assert data["delivery_id"] == "dlv-test-failed"
    assert "message" in data
    assert data["attempts"] >= 4
