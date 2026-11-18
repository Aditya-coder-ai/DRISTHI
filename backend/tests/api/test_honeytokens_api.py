"""API tests for Honeytoken Lifecycle Management."""

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def seed_parent_assets(client: TestClient):
    """Ensure baseline parent deceptive assets exist for honeytokens."""
    client.post("/api/assets", json={
        "asset_id": "web-001",
        "name": "Web Admin Portal",
        "asset_type": "http_honeypot",
        "environment": "production",
        "status": "active",
    })
    client.post("/api/assets", json={
        "asset_id": "ssh-001",
        "name": "Apex SSH Bastion",
        "asset_type": "ssh_honeypot",
        "environment": "production",
        "status": "active",
    })


def test_generate_and_register_honeytokens(client: TestClient):
    """Test generating realistic fake credentials and ensuring secret masking on retrieval."""
    # 1. Generate AWS IAM token
    res_aws = client.post("/api/honeytokens/generate", json={
        "asset_id": "web-001",
        "token_type": "aws_iam",
        "name": "AWS Production ReadOnly Key",
        "description": "Planted in /.aws/credentials decoy",
        "expires_in_days": 30,
        "metadata": {"path": "/.aws/credentials"},
    })
    assert res_aws.status_code == 201
    aws_data = res_aws.json()
    assert aws_data["token_id"].startswith("htk-aws-")
    assert aws_data["token_type"] == "aws_iam"
    assert aws_data["status"] == "active"
    assert "AKIA-CANARY-" in aws_data["token_value_masked"]
    assert "generated_credentials" in aws_data
    assert "access_key_id" in aws_data["generated_credentials"]
    assert "secret_access_key" in aws_data["generated_credentials"]

    # 2. Generate SSH credential
    res_ssh = client.post("/api/honeytokens/generate", json={
        "asset_id": "ssh-001",
        "token_type": "ssh_credential",
        "name": "SSH Backup Key",
        "description": "Planted in ~/.ssh/authorized_keys",
    })
    assert res_ssh.status_code == 201
    ssh_data = res_ssh.json()
    assert ssh_data["token_type"] == "ssh_credential"
    assert "password" in ssh_data["generated_credentials"]
    assert "public_key" in ssh_data["generated_credentials"]

    # 3. Generate Database credential
    res_db = client.post("/api/honeytokens/generate", json={
        "asset_id": "web-001",
        "token_type": "database_credential",
        "name": "Finance Read DB User",
    })
    assert res_db.status_code == 201
    db_data = res_db.json()
    assert db_data["token_type"] == "database_credential"
    assert "connection_string" in db_data["generated_credentials"]

    # 4. Generate API token
    res_api = client.post("/api/honeytokens/generate", json={
        "asset_id": "web-001",
        "token_type": "api_token",
        "name": "Stripe Decoy Webhook Key",
    })
    assert res_api.status_code == 201
    api_data = res_api.json()
    assert api_data["token_type"] == "api_token"
    assert "drishti_canary_live_" in api_data["generated_credentials"]["token"]

    # 5. Retrieve AWS token via GET -> Verify plaintext secret is NEVER present
    get_res = client.get(f"/api/honeytokens/{aws_data['token_id']}")
    assert get_res.status_code == 200
    token_detail = get_res.json()
    assert token_detail["token_id"] == aws_data["token_id"]
    assert "generated_credentials" not in token_detail
    assert "secret_access_key" not in token_detail
    assert "AKIA-CANARY-****-" in token_detail["token_value_masked"]


def test_honeytoken_listing_and_filtering(client: TestClient):
    """Test listing honeytokens with pagination, token_type, and status filters."""
    # Create multiple honeytokens
    client.post("/api/honeytokens/generate", json={
        "asset_id": "web-001",
        "token_type": "aws_iam",
        "name": "Decoy AWS 1",
    })
    client.post("/api/honeytokens/generate", json={
        "asset_id": "ssh-001",
        "token_type": "ssh_credential",
        "name": "Decoy SSH 1",
    })

    # 1. List all
    res = client.get("/api/honeytokens")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] >= 2
    assert len(data["items"]) >= 2

    # 2. Filter by token_type
    res_type = client.get("/api/honeytokens?token_type=aws_iam")
    assert res_type.status_code == 200
    assert all(it["token_type"] == "aws_iam" for it in res_type.json()["items"])

    # 3. Filter by asset_id
    res_asset = client.get("/api/honeytokens?asset_id=ssh-001")
    assert res_asset.status_code == 200
    assert all(it["asset_id"] == "ssh-001" for it in res_asset.json()["items"])

    # 4. Limit alias
    res_limit = client.get("/api/honeytokens?limit=1")
    assert res_limit.status_code == 200
    assert len(res_limit.json()["items"]) == 1
    assert res_limit.json()["limit"] == 1


def test_honeytoken_rotation_and_revocation(client: TestClient):
    """Test rotating an active token and revoking tokens."""
    # 1. Create token
    create_res = client.post("/api/honeytokens/generate", json={
        "asset_id": "web-001",
        "token_type": "api_token",
        "name": "Rotatable API Key",
    })
    old_id = create_res.json()["token_id"]

    # 2. Rotate token
    rotate_res = client.post(f"/api/honeytokens/{old_id}/rotate")
    assert rotate_res.status_code == 200
    rotated_data = rotate_res.json()
    new_id = rotated_data["token_id"]
    assert new_id != old_id
    assert rotated_data["status"] == "active"
    assert rotated_data["metadata"]["rotated_from"] == old_id

    # 3. Verify old token is now revoked
    old_get = client.get(f"/api/honeytokens/{old_id}")
    assert old_get.status_code == 200
    assert old_get.json()["status"] == "revoked"
    assert old_get.json()["metadata"]["rotated_to"] == new_id

    # 4. Explicitly revoke the new token
    revoke_res = client.post(f"/api/honeytokens/{new_id}/revoke")
    assert revoke_res.status_code == 200
    assert revoke_res.json()["status"] == "revoked"


def test_honeytoken_trigger_dispatch(client: TestClient):
    """Test triggering a honeytoken and verifying pipeline event generation."""
    # 1. Create token
    create_res = client.post("/api/honeytokens/generate", json={
        "asset_id": "web-001",
        "token_type": "aws_iam",
        "name": "Decoy AWS Root",
    })
    token_id = create_res.json()["token_id"]

    # 2. Trigger the token
    trigger_res = client.post(f"/api/honeytokens/{token_id}/trigger", json={
        "trigger_type": "iam_sts_get_caller_identity",
        "source_ip": "203.0.113.88",
        "source_port": 54221,
        "source_service": "web",
        "username": "suspicious_actor",
        "details": {"action": "sts:GetCallerIdentity", "user_agent": "aws-cli/2.15"},
    })
    assert trigger_res.status_code == 200
    trigger_data = trigger_res.json()
    assert trigger_data["status"] == "triggered"
    assert trigger_data["token"]["trigger_count"] == 1
    assert trigger_data["token"]["status"] == "triggered"
    assert trigger_data["pipeline_event"]["severity"] == "critical"
    assert trigger_data["pipeline_event"]["event_type"] == "canary_triggered"

    # 3. Verify event is persisted and retrievable via central events API
    events_res = client.get("/api/events?event_type=canary_triggered")
    assert events_res.status_code == 200
    events = events_res.json()["items"]
    assert any(e["event_id"] == trigger_data["pipeline_event"]["event_id"] for e in events)


def test_honeytoken_deletion(client: TestClient):
    """Test soft-delete (revocation) and hard-delete."""
    create_res = client.post("/api/honeytokens/generate", json={
        "asset_id": "ssh-001",
        "token_type": "ssh_credential",
        "name": "Deletable Token",
    })
    token_id = create_res.json()["token_id"]

    # 1. Soft-delete (default)
    del_soft = client.delete(f"/api/honeytokens/{token_id}")
    assert del_soft.status_code == 200
    assert del_soft.json()["action"] == "revoked"

    check_soft = client.get(f"/api/honeytokens/{token_id}")
    assert check_soft.status_code == 200
    assert check_soft.json()["status"] == "revoked"

    # 2. Hard-delete
    del_hard = client.delete(f"/api/honeytokens/{token_id}?hard=true")
    assert del_hard.status_code == 200
    assert del_hard.json()["action"] == "deleted"

    check_hard = client.get(f"/api/honeytokens/{token_id}")
    assert check_hard.status_code == 404
