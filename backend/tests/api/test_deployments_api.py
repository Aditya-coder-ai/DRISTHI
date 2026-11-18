"""API tests for Deployment Registration and Lifecycle Management."""

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def seed_parent_assets(client: TestClient):
    """Ensure baseline parent deceptive assets exist for deployment registration."""
    client.post("/api/assets", json={
        "asset_id": "ssh-001",
        "name": "Apex Core SSH Gateway",
        "asset_type": "ssh_honeypot",
        "environment": "production",
        "status": "active",
    })
    client.post("/api/assets", json={
        "asset_id": "ftp-001",
        "name": "Corporate Backup Storage FTP",
        "asset_type": "ftp_honeypot",
        "environment": "production",
        "status": "active",
    })
    client.post("/api/assets", json={
        "asset_id": "web-001",
        "name": "Web Admin Management Portal",
        "asset_type": "http_honeypot",
        "environment": "production",
        "status": "active",
    })
    client.post("/api/assets", json={
        "asset_id": "db-001",
        "name": "Apex Relational DB Cluster",
        "asset_type": "database_honeypot",
        "environment": "production",
        "status": "active",
    })


def test_register_deployment_success(client: TestClient):
    """Test successful self-registration of a deployed honeypot."""
    response = client.post("/api/deployments/register", json={
        "deployment_id": "deploy-ssh-prod-01",
        "asset_id": "ssh-001",
        "asset_type": "ssh_honeypot",
        "environment": "production",
        "version": "1.2.0",
        "hostname": "finance-ssh.internal",
        "ip_address": "10.0.1.50",
        "port": 2222,
        "deploy_metadata": {
            "container_id": "docker-ssh-9912",
            "jail": "cowrie",
        },
    })
    assert response.status_code == 201
    data = response.json()
    assert data["deployment_id"] == "deploy-ssh-prod-01"
    assert data["asset_id"] == "ssh-001"
    assert data["status"] == "registered"
    assert data["version"] == "1.2.0"
    assert data["hostname"] == "finance-ssh.internal"
    assert data["port"] == 2222
    assert data["deploy_metadata"]["container_id"] == "docker-ssh-9912"
    assert data["registered_at"] is not None


def test_register_deployment_upsert_idempotency(client: TestClient):
    """Test that re-registering the same deployment_id performs an idempotent update."""
    payload = {
        "deployment_id": "deploy-ftp-prod-01",
        "asset_id": "ftp-001",
        "asset_type": "ftp_honeypot",
        "environment": "production",
        "version": "1.0.0",
        "port": 2121,
    }
    res1 = client.post("/api/deployments/register", json=payload)
    assert res1.status_code == 201

    # Re-register with updated version and port
    payload["version"] = "1.0.1"
    payload["port"] = 2122
    res2 = client.post("/api/deployments/register", json=payload)
    assert res2.status_code == 201
    data = res2.json()
    assert data["deployment_id"] == "deploy-ftp-prod-01"
    assert data["version"] == "1.0.1"
    assert data["port"] == 2122
    assert data["last_heartbeat_at"] is not None


def test_register_deployment_nonexistent_asset_rejected(client: TestClient):
    """Test that registering a deployment against a non-existent asset ID is rejected."""
    response = client.post("/api/deployments/register", json={
        "deployment_id": "deploy-fake-01",
        "asset_id": "non-existent-asset-999",
        "asset_type": "ssh_honeypot",
    })
    assert response.status_code == 400
    assert "not found" in response.json()["detail"].lower()


def test_register_deployment_redacts_metadata_passwords(client: TestClient):
    """Ensure sensitive credentials in deployment metadata are properly redacted."""
    response = client.post("/api/deployments/register", json={
        "deployment_id": "deploy-web-prod-01",
        "asset_id": "web-001",
        "asset_type": "http_honeypot",
        "deploy_metadata": {
            "admin_password": "supersecretpassword123",
            "service_token_secret": "my-secret-key",
            "safe_config": "enabled",
        },
    })
    assert response.status_code == 201
    meta = response.json()["deploy_metadata"]
    assert "admin_password" not in meta
    assert meta.get("admin_password_redacted") is True
    assert meta.get("admin_password_length") == len("supersecretpassword123")
    assert meta.get("safe_config") == "enabled"


def test_list_deployments_with_filters(client: TestClient):
    """Test listing deployments with pagination and filtering."""
    # Register multiple deployments
    client.post("/api/deployments/register", json={
        "deployment_id": "dep-ssh",
        "asset_id": "ssh-001",
        "asset_type": "ssh_honeypot",
        "environment": "production",
    })
    client.post("/api/deployments/register", json={
        "deployment_id": "dep-ftp",
        "asset_id": "ftp-001",
        "asset_type": "ftp_honeypot",
        "environment": "staging",
    })

    # List all
    res_all = client.get("/api/deployments")
    assert res_all.status_code == 200
    items = res_all.json()["items"]
    assert len(items) >= 2

    # Filter by asset_type
    res_ssh = client.get("/api/deployments?asset_type=ssh_honeypot")
    assert res_ssh.status_code == 200
    assert all(it["asset_type"] == "ssh_honeypot" for it in res_ssh.json()["items"])

    # Filter by environment
    res_staging = client.get("/api/deployments?environment=staging")
    assert res_staging.status_code == 200
    assert all(it["environment"] == "staging" for it in res_staging.json()["items"])

    # Filter by asset_id
    res_asset = client.get("/api/deployments?asset_id=ssh-001")
    assert res_asset.status_code == 200
    assert all(it["asset_id"] == "ssh-001" for it in res_asset.json()["items"])


def test_get_deployment_by_id(client: TestClient):
    """Test retrieving deployment details by deployment_id."""
    client.post("/api/deployments/register", json={
        "deployment_id": "dep-db-01",
        "asset_id": "db-001",
        "asset_type": "database_honeypot",
        "hostname": "db-node-1.internal",
    })

    res = client.get("/api/deployments/dep-db-01")
    assert res.status_code == 200
    assert res.json()["deployment_id"] == "dep-db-01"
    assert res.json()["hostname"] == "db-node-1.internal"

    # Non-existent
    res_404 = client.get("/api/deployments/non-existent-dep")
    assert res_404.status_code == 404


def test_update_deployment_lifecycle_status(client: TestClient):
    """Test updating deployment status and verifying transition enforcement."""
    client.post("/api/deployments/register", json={
        "deployment_id": "dep-lifecycle-01",
        "asset_id": "ssh-001",
        "asset_type": "ssh_honeypot",
    })

    # Update to active
    res_active = client.put("/api/deployments/dep-lifecycle-01", json={
        "status": "active",
        "version": "2.0.0",
    })
    assert res_active.status_code == 200
    assert res_active.json()["status"] == "active"
    assert res_active.json()["version"] == "2.0.0"

    # Update to decommissioned
    res_decom = client.put("/api/deployments/dep-lifecycle-01", json={
        "status": "decommissioned",
    })
    assert res_decom.status_code == 200
    assert res_decom.json()["status"] == "decommissioned"

    # Reactivate from decommissioned (allowed explicit reactivation)
    res_reactivate = client.put("/api/deployments/dep-lifecycle-01", json={
        "status": "active",
    })
    assert res_reactivate.status_code == 200
    assert res_reactivate.json()["status"] == "active"


def test_deployment_heartbeat(client: TestClient):
    """Test recording heartbeats from deployed deceptive assets."""
    client.post("/api/deployments/register", json={
        "deployment_id": "dep-hb-01",
        "asset_id": "ssh-001",
        "asset_type": "ssh_honeypot",
    })

    # Send heartbeat
    res_hb = client.post("/api/deployments/dep-hb-01/heartbeat", json={
        "status": "active",
        "version": "1.5.0",
        "deploy_metadata": {"uptime_seconds": 3600},
    })
    assert res_hb.status_code == 200
    data = res_hb.json()
    assert data["status"] == "active"
    assert data["version"] == "1.5.0"
    assert data["last_heartbeat_at"] is not None
    assert data["deploy_metadata"]["uptime_seconds"] == 3600
