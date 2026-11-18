"""Integration tests for Honeytoken Lifecycle Management and Tenant Isolation."""

from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient

from backend.app.core.exceptions import CrossTenantAccessDeniedException
from backend.app.models.honeytoken import Honeytoken
from backend.app.schemas.honeytoken import HoneytokenCreate
from backend.app.services.honeytoken_service import HoneytokenService
from backend.app.services.tenant_data_access import TenantDataAccess


@pytest.fixture
def setup_tenants_and_assets(client: TestClient):
    """Seed two distinct tenants and baseline assets for tenant isolation tests."""
    # Tenant 1 (default): tenant-apex-001
    client.post("/api/assets", json={
        "asset_id": "asset-t1-web",
        "name": "Tenant 1 Web Host",
        "asset_type": "http_honeypot",
    }, headers={"X-Tenant-ID": "tenant-apex-001"})

    # Tenant 2: tenant-cyber-002
    client.post("/api/tenants", json={
        "tenant_id": "tenant-cyber-002",
        "name": "Cyber Defense Corp",
        "description": "Secondary enterprise tenant",
    })
    client.post("/api/assets", json={
        "asset_id": "asset-t2-web",
        "name": "Tenant 2 Web Host",
        "asset_type": "http_honeypot",
    }, headers={"X-Tenant-ID": "tenant-cyber-002"})


def test_cross_tenant_honeytoken_access_rejected(client: TestClient, setup_tenants_and_assets):
    """Verify that Tenant B cannot read, update, rotate, or trigger Tenant A's honeytokens."""
    # 1. Tenant 1 generates a honeytoken
    res_t1 = client.post("/api/honeytokens/generate", json={
        "asset_id": "asset-t1-web",
        "token_type": "aws_iam",
        "name": "T1 Production IAM Token",
    }, headers={"X-Tenant-ID": "tenant-apex-001"})
    assert res_t1.status_code == 201
    t1_token_id = res_t1.json()["token_id"]

    # 2. Tenant 2 tries to GET Tenant 1's honeytoken -> 403 Forbidden
    res_get_t2 = client.get(
        f"/api/honeytokens/{t1_token_id}",
        headers={"X-Tenant-ID": "tenant-cyber-002"}
    )
    assert res_get_t2.status_code == 403

    # 3. Tenant 2 tries to PUT/update Tenant 1's honeytoken -> 403 Forbidden
    res_put_t2 = client.put(
        f"/api/honeytokens/{t1_token_id}",
        json={"name": "Hacked Name"},
        headers={"X-Tenant-ID": "tenant-cyber-002"}
    )
    assert res_put_t2.status_code == 403

    # 4. Tenant 2 tries to ROTATE Tenant 1's honeytoken -> 403 Forbidden
    res_rotate_t2 = client.post(
        f"/api/honeytokens/{t1_token_id}/rotate",
        headers={"X-Tenant-ID": "tenant-cyber-002"}
    )
    assert res_rotate_t2.status_code == 403

    # 5. Tenant 2 tries to REVOKE Tenant 1's honeytoken -> 403 Forbidden
    res_revoke_t2 = client.post(
        f"/api/honeytokens/{t1_token_id}/revoke",
        headers={"X-Tenant-ID": "tenant-cyber-002"}
    )
    assert res_revoke_t2.status_code == 403

    # 6. Tenant 2 tries to TRIGGER Tenant 1's honeytoken -> 403 Forbidden
    res_trigger_t2 = client.post(
        f"/api/honeytokens/{t1_token_id}/trigger",
        json={"trigger_type": "canary_access"},
        headers={"X-Tenant-ID": "tenant-cyber-002"}
    )
    assert res_trigger_t2.status_code == 403

    # 7. Tenant 2 tries to bind a new honeytoken to Tenant 1's asset -> 403 Forbidden
    res_bind_t2 = client.post("/api/honeytokens/generate", json={
        "asset_id": "asset-t1-web",
        "token_type": "aws_iam",
        "name": "Cross-Tenant Plant Attempt",
    }, headers={"X-Tenant-ID": "tenant-cyber-002"})
    assert res_bind_t2.status_code == 403


def test_tenant_data_access_layer_direct_isolation(test_db, setup_tenants_and_assets):
    """Test that direct calls at TenantDataAccess layer raise CrossTenantAccessDeniedException."""
    service_t1 = HoneytokenService(test_db, "tenant-apex-001")
    token, _ = service_t1.register_honeytoken(HoneytokenCreate(
        token_id="htk-t1-direct-001",
        name="Direct T1 Token",
        token_type="api_token",
        asset_id="asset-t1-web",
    ))

    t2_access = TenantDataAccess(test_db, "tenant-cyber-002")

    # 1. Direct get_honeytoken against foreign token must raise CrossTenantAccessDeniedException
    with pytest.raises(CrossTenantAccessDeniedException):
        t2_access.get_honeytoken(token.token_id)

    # 2. Direct creation targeting foreign tenant must raise CrossTenantAccessDeniedException
    with pytest.raises(CrossTenantAccessDeniedException):
        t2_access.create_honeytoken(HoneytokenCreate(
            token_id="htk-t2-tamper",
            tenant_id="tenant-apex-001",  # tampering tenant
            name="Tamper Token",
            token_type="api_token",
            asset_id="asset-t1-web",
        ))


def test_ingestion_pipeline_updates_honeytoken_triggers(client: TestClient, setup_tenants_and_assets):
    """Test that central ingestion of a SecurityEvent referencing honeytoken_id updates trigger tracking."""
    # 1. Register honeytoken
    res_token = client.post("/api/honeytokens/generate", json={
        "asset_id": "asset-t1-web",
        "token_type": "ssh_credential",
        "name": "SSH Canary Login",
    }, headers={"X-Tenant-ID": "tenant-apex-001"})
    assert res_token.status_code == 201
    token_id = res_token.json()["token_id"]

    # 2. Ingest security event matching this honeytoken
    ingest_payload = {
        "event_id": "evt-htk-trigger-999",
        "tenant_id": "tenant-apex-001",
        "asset_id": "asset-t1-web",
        "honeytoken_id": token_id,
        "event_type": "canary_triggered",
        "source_ip": "198.51.100.77",
        "source_service": "ssh",
        "metadata": {
            "honeytoken_id": token_id,
            "action": "bait_credential_login",
        },
    }

    res_ingest = client.post("/api/ingest", json=ingest_payload)
    assert res_ingest.status_code in (200, 201)
    assert res_ingest.json()["persisted"] == 1

    # 3. Verify honeytoken trigger count updated and status is triggered
    token_check = client.get(
        f"/api/honeytokens/{token_id}",
        headers={"X-Tenant-ID": "tenant-apex-001"}
    )
    assert token_check.status_code == 200
    data = token_check.json()
    assert data["trigger_count"] == 1
    assert data["status"] == "triggered"
    assert data["last_triggered_at"] is not None


def test_honeytoken_expiration_handling(client: TestClient, test_db, setup_tenants_and_assets):
    """Verify that expired tokens dynamically transition to 'expired' status."""
    expired_time = datetime.now(timezone.utc) - timedelta(hours=2)

    # Directly insert token with past expiration
    service_t1 = HoneytokenService(test_db, "tenant-apex-001")
    token, _ = service_t1.register_honeytoken(HoneytokenCreate(
        token_id="htk-expired-001",
        name="Expired Token Test",
        token_type="aws_iam",
        asset_id="asset-t1-web",
        expires_at=expired_time,
    ))

    # Retrieve via API
    res = client.get(
        f"/api/honeytokens/{token.token_id}",
        headers={"X-Tenant-ID": "tenant-apex-001"}
    )
    assert res.status_code == 200
    assert res.json()["status"] == "expired"
