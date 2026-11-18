"""API tests for Integration Configuration Management."""

import pytest
from fastapi.testclient import TestClient


def test_create_webhook_integration_with_secret(client: TestClient):
    """Test creating a webhook integration, verifying secret masking and safe validation."""
    response = client.post("/api/integrations", json={
        "integration_id": "intg-webhook-slack-01",
        "name": "SecOps Slack Incident Channel",
        "integration_type": "webhook",
        "config_metadata": {
            "url": "https://hooks.slack.com/services/T00/B00/X00",
            "http_method": "POST",
        },
        "secret": "whsec_supersecrettoken1234567890",
        "enabled": True,
    })
    assert response.status_code == 201
    data = response.json()
    assert data["integration_id"] == "intg-webhook-slack-01"
    assert data["name"] == "SecOps Slack Incident Channel"
    assert data["integration_type"] == "webhook"
    assert data["enabled"] is True
    assert data["status"] == "verified"  # Auto-validated on creation
    assert data["has_secret"] is True
    assert "whsec_supersecrettoken1234567890" not in str(data)  # Plaintext never exposed
    assert data["secret_masked"] is not None
    assert "whsec_" in data["secret_masked"]
    assert "****" in data["secret_masked"]


def test_create_siem_integration_and_auto_id(client: TestClient):
    """Test creating a SIEM integration without explicit ID, verifying auto-generated ID."""
    response = client.post("/api/integrations", json={
        "name": "Corporate Splunk HEC",
        "integration_type": "siem",
        "config_metadata": {
            "host": "splunk.corp.internal",
            "port": 8088,
            "format": "json",
            "index": "drishti_threats",
        },
        "secret": "SplunkHEC-Token-abcdef123456",
    })
    assert response.status_code == 201
    data = response.json()
    assert data["integration_id"].startswith("intg-siem-")
    assert data["integration_type"] == "siem"
    assert data["status"] == "verified"
    assert data["has_secret"] is True


def test_create_integration_metadata_password_redaction(client: TestClient):
    """Test that passwords accidentally placed inside config_metadata are safely redacted."""
    response = client.post("/api/integrations", json={
        "name": "QRadar SIEM",
        "integration_type": "siem",
        "config_metadata": {
            "host": "qradar.internal",
            "port": 514,
            "format": "syslog",
            "admin_password": "PlaintextPasswordInMetadata!",
            "api_key": "raw_api_key_value",
        },
    })
    assert response.status_code == 201
    meta = response.json()["config_metadata"]
    assert "admin_password" not in meta
    assert meta.get("admin_password_redacted") is True
    assert meta.get("admin_password_length") == len("PlaintextPasswordInMetadata!")
    assert meta.get("api_key_redacted") is True


def test_duplicate_integration_id_rejected(client: TestClient):
    """Test that registering an existing integration_id returns a 400 conflict."""
    payload = {
        "integration_id": "intg-dup-01",
        "name": "First Instance",
        "integration_type": "webhook",
        "config_metadata": {"url": "https://example.com/hook"},
    }
    res1 = client.post("/api/integrations", json=payload)
    assert res1.status_code == 201

    res2 = client.post("/api/integrations", json=payload)
    assert res2.status_code == 400
    assert "already exists" in res2.json()["detail"].lower()


def test_list_integrations_with_filters(client: TestClient):
    """Test listing integrations with pagination and filtering."""
    client.post("/api/integrations", json={
        "integration_id": "intg-list-webhook",
        "name": "Discord Webhook",
        "integration_type": "webhook",
        "config_metadata": {"url": "https://discord.com/api/webhooks/123"},
        "enabled": True,
    })
    client.post("/api/integrations", json={
        "integration_id": "intg-list-siem",
        "name": "Elastic SIEM",
        "integration_type": "siem",
        "config_metadata": {"host": "elastic.internal", "port": 9200},
        "enabled": False,
    })

    # List all
    res_all = client.get("/api/integrations")
    assert res_all.status_code == 200
    items = res_all.json()["items"]
    assert len(items) >= 2

    # Filter by integration_type
    res_wh = client.get("/api/integrations?integration_type=webhook")
    assert res_wh.status_code == 200
    assert all(it["integration_type"] == "webhook" for it in res_wh.json()["items"])

    # Filter by enabled
    res_en = client.get("/api/integrations?enabled=false")
    assert res_en.status_code == 200
    assert all(it["enabled"] is False for it in res_en.json()["items"])

    # Search filter
    res_search = client.get("/api/integrations?search=Discord")
    assert res_search.status_code == 200
    assert any("Discord" in it["name"] for it in res_search.json()["items"])


def test_get_and_update_integration(client: TestClient):
    """Test retrieving and updating an integration configuration."""
    client.post("/api/integrations", json={
        "integration_id": "intg-update-01",
        "name": "Original Name",
        "integration_type": "webhook",
        "config_metadata": {"url": "https://example.com/v1"},
        "secret": "initial_secret_12345",
    })

    # 1. Retrieve
    res_get = client.get("/api/integrations/intg-update-01")
    assert res_get.status_code == 200
    assert res_get.json()["name"] == "Original Name"
    assert res_get.json()["has_secret"] is True

    # 2. Update name and metadata
    res_put = client.put("/api/integrations/intg-update-01", json={
        "name": "Updated Name V2",
        "config_metadata": {"url": "https://example.com/v2"},
    })
    assert res_put.status_code == 200
    assert res_put.json()["name"] == "Updated Name V2"
    assert res_put.json()["config_metadata"]["url"] == "https://example.com/v2"
    assert res_put.json()["has_secret"] is True  # Preserved


def test_secret_rotation_and_revocation(client: TestClient):
    """Test rotating an integration secret and explicitly revoking it."""
    client.post("/api/integrations", json={
        "integration_id": "intg-sec-ops-01",
        "name": "Secret Ops Integration",
        "integration_type": "webhook",
        "config_metadata": {"url": "https://example.com/hook"},
        "secret": "old_secret_key_1111",
    })

    # Rotate secret
    res_rotate = client.put("/api/integrations/intg-sec-ops-01", json={
        "secret": "new_rotated_secret_9999",
    })
    assert res_rotate.status_code == 200
    rot_data = res_rotate.json()
    assert rot_data["has_secret"] is True
    assert rot_data["secret_masked"] != "old_secret_key_1111"
    assert "new_rotated_secret_9999" not in str(rot_data)

    # Revoke secret
    res_revoke = client.put("/api/integrations/intg-sec-ops-01", json={
        "revoke_secret": True,
    })
    assert res_revoke.status_code == 200
    rev_data = res_revoke.json()
    assert rev_data["has_secret"] is False
    assert rev_data["secret_masked"] is None


def test_toggle_integration_state(client: TestClient):
    """Test enabling and disabling an integration via toggle endpoint."""
    client.post("/api/integrations", json={
        "integration_id": "intg-toggle-01",
        "name": "Toggle Test",
        "integration_type": "webhook",
        "config_metadata": {"url": "https://example.com/toggle"},
        "enabled": True,
    })

    # Toggle off (flips to False)
    res_off = client.patch("/api/integrations/intg-toggle-01/toggle")
    assert res_off.status_code == 200
    assert res_off.json()["enabled"] is False
    assert res_off.json()["status"] == "disabled"

    # Explicit toggle on
    res_on = client.patch("/api/integrations/intg-toggle-01/toggle?enabled=true")
    assert res_on.status_code == 200
    assert res_on.json()["enabled"] is True
    assert res_on.json()["status"] == "configured"


def test_delete_integration(client: TestClient):
    """Test permanently deleting an integration configuration."""
    client.post("/api/integrations", json={
        "integration_id": "intg-del-01",
        "name": "To Be Deleted",
        "integration_type": "webhook",
        "config_metadata": {"url": "https://example.com/delete"},
    })

    res_del = client.delete("/api/integrations/intg-del-01")
    assert res_del.status_code == 200
    assert res_del.json()["status"] == "deleted"

    # Subsequent GET returns 404
    res_get = client.get("/api/integrations/intg-del-01")
    assert res_get.status_code == 404


def test_safe_configuration_validation_endpoint(client: TestClient):
    """Test safe configuration validation without firing outbound network requests."""
    # 1. Valid webhook
    client.post("/api/integrations", json={
        "integration_id": "intg-valid-wh",
        "name": "Valid Hook",
        "integration_type": "webhook",
        "config_metadata": {"url": "https://api.security.corp/webhook", "http_method": "POST"},
    })
    res_val1 = client.post("/api/integrations/intg-valid-wh/validate")
    assert res_val1.status_code == 200
    v1 = res_val1.json()
    assert v1["is_valid"] is True
    assert v1["status"] == "verified"
    assert len(v1["details"]["errors"]) == 0
    assert "url" in v1["details"]["validated_fields"]

    # 2. Invalid SIEM configuration (missing host, invalid port)
    client.post("/api/integrations", json={
        "integration_id": "intg-invalid-siem",
        "name": "Invalid SIEM",
        "integration_type": "siem",
        "config_metadata": {"port": 999999, "format": "unknown_format"},
    })
    res_val2 = client.post("/api/integrations/intg-invalid-siem/validate")
    assert res_val2.status_code == 200
    v2 = res_val2.json()
    assert v2["is_valid"] is False
    assert v2["status"] == "error"
    assert any("host" in e.lower() for e in v2["details"]["errors"])
    assert any("port" in e.lower() for e in v2["details"]["errors"])
