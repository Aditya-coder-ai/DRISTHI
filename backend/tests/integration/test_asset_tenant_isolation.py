"""Integration tests for Asset Registry Tenant Isolation and Access Enforcement."""

import pytest
from sqlalchemy.orm import Session
from fastapi.testclient import TestClient

from backend.app.core.exceptions import CrossTenantAccessDeniedException
from backend.app.models.asset import DeceptiveAsset
from backend.app.schemas.asset import AssetCreate, AssetUpdate
from backend.app.services.tenant_data_access import TenantDataAccess


def test_multi_tenant_asset_isolation(client: TestClient):
    """Test that assets registered under different tenants are strictly isolated."""
    # Ensure tenants exist
    client.post("/api/tenants", json={"tenant_id": "tenant-corp-a", "name": "Corp A"})
    client.post("/api/tenants", json={"tenant_id": "tenant-corp-b", "name": "Corp B"})

    # Register asset under Corp A
    res_a = client.post(
        "/api/assets",
        json={
            "asset_id": "ssh-corp-a-01",
            "name": "Corp A SSH Server",
            "asset_type": "ssh_honeypot",
            "status": "active",
        },
        headers={"X-Tenant-ID": "tenant-corp-a"},
    )
    assert res_a.status_code == 201
    assert res_a.json()["tenant_id"] == "tenant-corp-a"

    # Register asset under Corp B
    res_b = client.post(
        "/api/assets",
        json={
            "asset_id": "ftp-corp-b-01",
            "name": "Corp B Backup FTP",
            "asset_type": "ftp_honeypot",
            "status": "active",
        },
        headers={"X-Tenant-ID": "tenant-corp-b"},
    )
    assert res_b.status_code == 201
    assert res_b.json()["tenant_id"] == "tenant-corp-b"

    # 1. Corp A queries assets -> only receives Corp A assets
    res_list_a = client.get("/api/assets", headers={"X-Tenant-ID": "tenant-corp-a"})
    assert res_list_a.status_code == 200
    ids_a = [it["asset_id"] for it in res_list_a.json()["items"]]
    assert "ssh-corp-a-01" in ids_a
    assert "ftp-corp-b-01" not in ids_a

    # 2. Corp B queries assets -> only receives Corp B assets
    res_list_b = client.get("/api/assets", headers={"X-Tenant-ID": "tenant-corp-b"})
    assert res_list_b.status_code == 200
    ids_b = [it["asset_id"] for it in res_list_b.json()["items"]]
    assert "ftp-corp-b-01" in ids_b
    assert "ssh-corp-a-01" not in ids_b


def test_cross_tenant_asset_access_rejected(client: TestClient):
    """Test that cross-tenant retrieval, modification, deletion, and registration are rejected with 403."""
    client.post("/api/tenants", json={"tenant_id": "tenant-owner", "name": "Owner Corp"})
    client.post("/api/tenants", json={"tenant_id": "tenant-attacker", "name": "Attacker Corp"})

    # Owner registers an asset
    client.post(
        "/api/assets",
        json={
            "asset_id": "secret-db-asset-01",
            "name": "Classified Financial DB Decoy",
            "asset_type": "database_honeypot",
            "status": "active",
        },
        headers={"X-Tenant-ID": "tenant-owner"},
    )

    # 1. Attacker tenant tries to retrieve Owner's asset -> 403 Forbidden
    res_get = client.get(
        "/api/assets/secret-db-asset-01",
        headers={"X-Tenant-ID": "tenant-attacker"},
    )
    assert res_get.status_code == 403
    assert "Access denied" in res_get.json()["detail"]

    # 2. Attacker tenant tries to update Owner's asset -> 403 Forbidden
    res_put = client.put(
        "/api/assets/secret-db-asset-01",
        json={"name": "Tampered Name"},
        headers={"X-Tenant-ID": "tenant-attacker"},
    )
    assert res_put.status_code == 403
    assert "Access denied" in res_put.json()["detail"]

    # 3. Attacker tenant tries to delete Owner's asset -> 403 Forbidden
    res_del = client.delete(
        "/api/assets/secret-db-asset-01",
        headers={"X-Tenant-ID": "tenant-attacker"},
    )
    assert res_del.status_code == 403
    assert "Access denied" in res_del.json()["detail"]

    # 4. Attacker attempts to register an asset specifying tenant-owner in request body -> 403 Forbidden
    res_cross_reg = client.post(
        "/api/assets",
        json={
            "asset_id": "malicious-asset-01",
            "tenant_id": "tenant-owner",
            "name": "Malicious Spoofed Decoy",
            "asset_type": "ssh_honeypot",
        },
        headers={"X-Tenant-ID": "tenant-attacker"},
    )
    assert res_cross_reg.status_code == 403
    assert "Unauthorized" in res_cross_reg.json()["detail"]


def test_asset_data_access_layer_direct_isolation(test_db: Session):
    """Directly test TenantDataAccess asset enforcement methods."""
    da_alpha = TenantDataAccess(test_db, tenant_id="tenant-alpha")
    da_beta = TenantDataAccess(test_db, tenant_id="tenant-beta")

    # Register asset via da_alpha
    asset_create = AssetCreate(
        asset_id="ssh-da-001",
        name="Alpha SSH",
        asset_type="ssh_honeypot",
        status="active",
    )
    created = da_alpha.create_asset(asset_create)
    assert created.tenant_id == "tenant-alpha"

    # 1. Alpha can read own asset
    read_alpha = da_alpha.get_asset("ssh-da-001")
    assert read_alpha is not None
    assert read_alpha.asset_id == "ssh-da-001"

    # 2. Beta calling get_asset raises CrossTenantAccessDeniedException
    with pytest.raises(CrossTenantAccessDeniedException) as exc_info:
        da_beta.get_asset("ssh-da-001")
    assert "Access denied" in str(exc_info.value)

    # 3. Beta calling update_asset raises CrossTenantAccessDeniedException
    with pytest.raises(CrossTenantAccessDeniedException):
        da_beta.update_asset("ssh-da-001", AssetUpdate(name="Hacked Name"))

    # 4. Beta calling delete_asset raises CrossTenantAccessDeniedException
    with pytest.raises(CrossTenantAccessDeniedException):
        da_beta.delete_asset("ssh-da-001")

    # 5. List query strictly isolated
    items_alpha, total_alpha = da_alpha.list_assets()
    items_beta, total_beta = da_beta.list_assets()
    assert total_alpha == 1
    assert total_beta == 0
