"""Integration tests for Multi-Tenant Isolation of Deployment Registration."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.app.core.exceptions import CrossTenantAccessDeniedException
from backend.app.models.tenant import Tenant
from backend.app.schemas.asset import AssetCreate
from backend.app.schemas.deployment import DeploymentRegisterRequest, DeploymentUpdate
from backend.app.services.tenant_data_access import TenantDataAccess


TENANT_A = "tenant-apex-001"
TENANT_B = "tenant-cyber-002"


@pytest.fixture(autouse=True)
def setup_tenants_and_assets(test_db: Session):
    """Seed test tenants and baseline assets in each tenant."""
    # Ensure tenants exist
    t1 = test_db.query(Tenant).filter(Tenant.tenant_id == TENANT_A).first()
    if not t1:
        test_db.add(Tenant(tenant_id=TENANT_A, name="Apex Tenant", is_active=True))

    t2 = test_db.query(Tenant).filter(Tenant.tenant_id == TENANT_B).first()
    if not t2:
        test_db.add(Tenant(tenant_id=TENANT_B, name="Cyber Tenant", is_active=True))

    test_db.commit()

    # Seed an asset in Tenant A
    da_a = TenantDataAccess(test_db, TENANT_A)
    da_a.create_asset(AssetCreate(
        asset_id="asset-tenant-a-01",
        name="Tenant A SSH",
        asset_type="ssh_honeypot",
        environment="production",
    ))

    # Seed an asset in Tenant B
    da_b = TenantDataAccess(test_db, TENANT_B)
    da_b.create_asset(AssetCreate(
        asset_id="asset-tenant-b-01",
        name="Tenant B HTTP",
        asset_type="http_honeypot",
        environment="staging",
    ))


def test_deployment_listing_isolated_by_tenant(client: TestClient):
    """Deployments registered in Tenant A must not appear in Tenant B's listing."""
    # Register deployment in Tenant A
    res_a = client.post(
        "/api/deployments/register",
        headers={"X-Tenant-ID": TENANT_A},
        json={
            "deployment_id": "deploy-tenant-a-ssh",
            "asset_id": "asset-tenant-a-01",
            "asset_type": "ssh_honeypot",
        },
    )
    assert res_a.status_code == 201

    # Register deployment in Tenant B
    res_b = client.post(
        "/api/deployments/register",
        headers={"X-Tenant-ID": TENANT_B},
        json={
            "deployment_id": "deploy-tenant-b-web",
            "asset_id": "asset-tenant-b-01",
            "asset_type": "http_honeypot",
        },
    )
    assert res_b.status_code == 201

    # Tenant A lists deployments -> should only see Tenant A's deployment
    list_a = client.get("/api/deployments", headers={"X-Tenant-ID": TENANT_A})
    assert list_a.status_code == 200
    ids_a = [it["deployment_id"] for it in list_a.json()["items"]]
    assert "deploy-tenant-a-ssh" in ids_a
    assert "deploy-tenant-b-web" not in ids_a

    # Tenant B lists deployments -> should only see Tenant B's deployment
    list_b = client.get("/api/deployments", headers={"X-Tenant-ID": TENANT_B})
    assert list_b.status_code == 200
    ids_b = [it["deployment_id"] for it in list_b.json()["items"]]
    assert "deploy-tenant-b-web" in ids_b
    assert "deploy-tenant-a-ssh" not in ids_b


def test_cross_tenant_deployment_access_rejected(client: TestClient):
    """Tenant B cannot read, update, or heartbeat Tenant A's deployment."""
    # Register deployment in Tenant A
    client.post(
        "/api/deployments/register",
        headers={"X-Tenant-ID": TENANT_A},
        json={
            "deployment_id": "deploy-private-a",
            "asset_id": "asset-tenant-a-01",
            "asset_type": "ssh_honeypot",
        },
    )

    # Tenant B attempts to read Tenant A's deployment -> 403 Forbidden
    res_read = client.get("/api/deployments/deploy-private-a", headers={"X-Tenant-ID": TENANT_B})
    assert res_read.status_code == 403
    assert "access denied" in res_read.json()["detail"].lower()

    # Tenant B attempts to update Tenant A's deployment -> 403 Forbidden
    res_update = client.put(
        "/api/deployments/deploy-private-a",
        headers={"X-Tenant-ID": TENANT_B},
        json={"status": "decommissioned"},
    )
    assert res_update.status_code == 403
    assert "access denied" in res_update.json()["detail"].lower()

    # Tenant B attempts to heartbeat Tenant A's deployment -> 403 Forbidden
    res_hb = client.post(
        "/api/deployments/deploy-private-a/heartbeat",
        headers={"X-Tenant-ID": TENANT_B},
        json={"status": "active"},
    )
    assert res_hb.status_code == 403
    assert "access denied" in res_hb.json()["detail"].lower()


def test_cross_tenant_asset_reference_rejected_at_registration(client: TestClient):
    """Tenant B cannot register a deployment targeting Tenant A's asset."""
    res = client.post(
        "/api/deployments/register",
        headers={"X-Tenant-ID": TENANT_B},
        json={
            "deployment_id": "deploy-impostor",
            "asset_id": "asset-tenant-a-01",  # Belongs to Tenant A!
            "asset_type": "ssh_honeypot",
        },
    )
    assert res.status_code == 403
    assert "access denied" in res.json()["detail"].lower()


def test_tenant_data_access_layer_direct_deployment_isolation(test_db: Session):
    """Direct TenantDataAccess calls must enforce cross-tenant boundaries."""
    da_a = TenantDataAccess(test_db, TENANT_A)
    da_b = TenantDataAccess(test_db, TENANT_B)

    # Register deployment in Tenant A
    dep_a = da_a.register_deployment(DeploymentRegisterRequest(
        deployment_id="direct-dep-a",
        asset_id="asset-tenant-a-01",
        asset_type="ssh_honeypot",
    ))
    assert dep_a.deployment_id == "direct-dep-a"

    # da_b.get_deployment("direct-dep-a") must raise CrossTenantAccessDeniedException
    with pytest.raises(CrossTenantAccessDeniedException):
        da_b.get_deployment("direct-dep-a")

    # da_b.update_deployment("direct-dep-a") must raise CrossTenantAccessDeniedException
    with pytest.raises(CrossTenantAccessDeniedException):
        da_b.update_deployment("direct-dep-a", DeploymentUpdate(status="active"))

    # da_b.record_heartbeat("direct-dep-a") must raise CrossTenantAccessDeniedException
    with pytest.raises(CrossTenantAccessDeniedException):
        da_b.record_heartbeat("direct-dep-a", status="active")
