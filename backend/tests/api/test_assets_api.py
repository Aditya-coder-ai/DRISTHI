"""API tests for Centralized Deceptive Asset Registry endpoints."""

from fastapi.testclient import TestClient


def test_asset_registration_and_detail(client: TestClient):
    """Test registering a new deceptive asset, retrieving details, and 404 behavior."""
    payload = {
        "asset_id": "ssh-custom-001",
        "name": "Custom DMZ SSH Bastion",
        "asset_type": "ssh_honeypot",
        "description": "Emulated perimeter bastion host",
        "deployment_id": "deploy-dmz-01",
        "environment": "production",
        "status": "active",
        "config_metadata": {"port": 2222, "os": "Ubuntu 22.04"},
    }

    # 1. Register asset
    res = client.post("/api/assets", json=payload)
    assert res.status_code == 201
    data = res.json()
    assert data["asset_id"] == "ssh-custom-001"
    assert data["name"] == "Custom DMZ SSH Bastion"
    assert data["status"] == "active"
    assert data["tenant_id"] == "tenant-apex-001"

    # 2. Get asset by ID
    res_get = client.get("/api/assets/ssh-custom-001")
    assert res_get.status_code == 200
    assert res_get.json()["asset_id"] == "ssh-custom-001"

    # 3. 404 on nonexistent asset
    res_404 = client.get("/api/assets/nonexistent-asset-999")
    assert res_404.status_code == 404

    # 4. Duplicate asset ID rejected with 409
    res_dup = client.post("/api/assets", json=payload)
    assert res_dup.status_code == 409


def test_asset_listing_and_filtering(client: TestClient):
    """Test listing assets with type, status, and search filters."""
    # Register diverse assets
    client.post("/api/assets", json={
        "asset_id": "ftp-test-01",
        "name": "Financial Vault FTP",
        "asset_type": "ftp_honeypot",
        "environment": "production",
        "status": "active",
    })
    client.post("/api/assets", json={
        "asset_id": "token-test-01",
        "name": "Fake Cloud Key Token",
        "asset_type": "honeytoken",
        "environment": "staging",
        "status": "suspended",
    })

    # 1. List all assets
    res = client.get("/api/assets")
    assert res.status_code == 200
    items = res.json()["items"]
    asset_ids = [item["asset_id"] for item in items]
    assert "ftp-test-01" in asset_ids
    assert "token-test-01" in asset_ids

    # 2. Filter by asset_type
    res_type = client.get("/api/assets?asset_type=ftp_honeypot")
    assert res_type.status_code == 200
    assert all(it["asset_type"] == "ftp_honeypot" for it in res_type.json()["items"])

    # 3. Filter by status
    res_status = client.get("/api/assets?status=suspended")
    assert res_status.status_code == 200
    assert all(it["status"] == "suspended" for it in res_status.json()["items"])

    # 4. Filter by environment
    res_env = client.get("/api/assets?environment=staging")
    assert res_env.status_code == 200
    assert any(it["environment"] == "staging" for it in res_env.json()["items"])

    # 5. Search query
    res_search = client.get("/api/assets?search=Vault")
    assert res_search.status_code == 200
    assert len(res_search.json()["items"]) >= 1
    assert "Vault" in res_search.json()["items"][0]["name"]

    # 6. Pagination limit alias
    res_limit = client.get("/api/assets?limit=1")
    assert res_limit.status_code == 200
    data = res_limit.json()
    assert data["limit"] == 1
    assert len(data["items"]) == 1


def test_asset_lifecycle_update_and_decommission(client: TestClient):
    """Test updating asset properties and valid/invalid status transitions."""
    client.post("/api/assets", json={
        "asset_id": "db-lifecycle-01",
        "name": "Customer DB Decoy",
        "asset_type": "database_honeypot",
        "status": "active",
    })

    # 1. Update properties
    update_payload = {
        "name": "Customer DB Decoy v2",
        "description": "Updated database decoy cluster",
        "status": "suspended",
    }
    res_up = client.put("/api/assets/db-lifecycle-01", json=update_payload)
    assert res_up.status_code == 200
    updated = res_up.json()
    assert updated["name"] == "Customer DB Decoy v2"
    assert updated["status"] == "suspended"
    assert updated["description"] == "Updated database decoy cluster"

    # 2. Decommission asset via DELETE
    res_del = client.delete("/api/assets/db-lifecycle-01")
    assert res_del.status_code == 200
    assert res_del.json()["status"] == "decommissioned"

    # Verify status changed to decommissioned
    res_verify = client.get("/api/assets/db-lifecycle-01")
    assert res_verify.status_code == 200
    assert res_verify.json()["status"] == "decommissioned"


def test_metadata_sensitive_credential_sanitization(client: TestClient):
    """Test that sensitive credentials or secrets in config_metadata are sanitized."""
    payload = {
        "asset_id": "token-cred-01",
        "name": "Canary Secret Token",
        "asset_type": "honeytoken",
        "config_metadata": {
            "api_password": "super_secret_raw_password",
            "access_key_id": "AKIAEXAMPLE123456",
            "private_key": "-----BEGIN RSA PRIVATE KEY-----...",
        },
    }
    res = client.post("/api/assets", json=payload)
    assert res.status_code == 201
    meta = res.json()["config_metadata"]

    # Raw secrets must never appear in metadata
    assert "super_secret_raw_password" not in str(meta)
    assert "api_password_redacted" in meta
    assert meta["api_password_length"] == len("super_secret_raw_password")
    assert meta["private_key_redacted"] is True
