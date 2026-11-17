"""Integration tests for Multi-Tenant Isolation and Data-Access Layer boundaries."""

from datetime import datetime, timezone
import pytest
from sqlalchemy.orm import Session

from backend.app.core.exceptions import CrossTenantAccessDeniedException
from backend.app.models.tenant import Tenant
from backend.app.models.event import AttackEvent
from backend.app.models.session import AttackerSession
from backend.app.models.attacker import AttackerProfile
from backend.app.services.tenant_data_access import TenantDataAccess


def test_tenant_creation_and_identification(client):
    """Test creating and retrieving tenant identities."""
    # 1. Create a new tenant
    create_payload = {
        "tenant_id": "tenant-bravo-999",
        "name": "Bravo Financial Systems",
        "description": "Isolated financial decoy enclave",
    }
    res = client.post("/api/tenants", json=create_payload)
    assert res.status_code == 201
    data = res.json()
    assert data["tenant_id"] == "tenant-bravo-999"
    assert data["name"] == "Bravo Financial Systems"
    assert data["is_active"] is True

    # 2. Duplicate tenant creation rejected with 409
    res_dup = client.post("/api/tenants", json=create_payload)
    assert res_dup.status_code == 409

    # 3. Retrieve tenant by ID
    res_get = client.get("/api/tenants/tenant-bravo-999")
    assert res_get.status_code == 200
    assert res_get.json()["tenant_id"] == "tenant-bravo-999"

    # 4. List all tenants
    res_list = client.get("/api/tenants")
    assert res_list.status_code == 200
    tenants = res_list.json()
    tenant_ids = [t["tenant_id"] for t in tenants]
    assert "tenant-bravo-999" in tenant_ids


def test_tenant_scoped_data_retrieval(client):
    """Test that events, sessions, and attackers are strictly partitioned by tenant."""
    # Ensure tenants exist
    client.post("/api/tenants", json={"tenant_id": "tenant-alpha", "name": "Alpha Corp"})
    client.post("/api/tenants", json={"tenant_id": "tenant-beta", "name": "Beta Corp"})

    # Ingest event for Tenant Alpha
    alpha_event = {
        "event_id": "evt-alpha-001",
        "tenant_id": "tenant-alpha",
        "asset_id": "ssh-alpha-01",
        "event_type": "command_execution",
        "source_ip": "198.51.100.50",
        "source_port": 44100,
        "username": "alpha_user",
        "protocol": "SSH",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "status": "executed",
        "metadata": {"command": "whoami"},
    }
    res_a = client.post("/api/events", json=alpha_event)
    assert res_a.status_code == 201

    # Ingest event for Tenant Beta (same source IP to verify IP sharing without profile cross-talk)
    beta_event = {
        "event_id": "evt-beta-001",
        "tenant_id": "tenant-beta",
        "asset_id": "ftp-beta-01",
        "event_type": "file_download",
        "source_ip": "198.51.100.50",
        "source_port": 44102,
        "username": "beta_user",
        "protocol": "FTP",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "status": "success",
        "metadata": {"path": "/secret.pdf"},
    }
    res_b = client.post("/api/events", json=beta_event)
    assert res_b.status_code == 201

    # 1. Query events as Tenant Alpha
    res_alpha_events = client.get("/api/events", headers={"X-Tenant-ID": "tenant-alpha"})
    assert res_alpha_events.status_code == 200
    alpha_items = res_alpha_events.json()["items"]
    assert len(alpha_items) == 1
    assert alpha_items[0]["event_id"] == "evt-alpha-001"
    assert alpha_items[0]["tenant_id"] == "tenant-alpha"

    # 2. Query events as Tenant Beta
    res_beta_events = client.get("/api/events", headers={"X-Tenant-ID": "tenant-beta"})
    assert res_beta_events.status_code == 200
    beta_items = res_beta_events.json()["items"]
    assert len(beta_items) == 1
    assert beta_items[0]["event_id"] == "evt-beta-001"
    assert beta_items[0]["tenant_id"] == "tenant-beta"

    # 3. Query events with tenant_id query param
    res_query_param = client.get("/api/events?tenant_id=tenant-beta")
    assert res_query_param.status_code == 200
    assert len(res_query_param.json()["items"]) == 1
    assert res_query_param.json()["items"][0]["event_id"] == "evt-beta-001"

    # 4. Check sessions separation
    res_alpha_sess = client.get("/api/sessions", headers={"X-Tenant-ID": "tenant-alpha"})
    assert res_alpha_sess.status_code == 200
    assert len(res_alpha_sess.json()["items"]) == 1
    assert res_alpha_sess.json()["items"][0]["tenant_id"] == "tenant-alpha"

    res_beta_sess = client.get("/api/sessions", headers={"X-Tenant-ID": "tenant-beta"})
    assert res_beta_sess.status_code == 200
    assert len(res_beta_sess.json()["items"]) == 1
    assert res_beta_sess.json()["items"][0]["tenant_id"] == "tenant-beta"

    # 5. Check attacker profiles separation despite identical source_ip
    res_alpha_atk = client.get("/api/attackers", headers={"X-Tenant-ID": "tenant-alpha"})
    assert res_alpha_atk.status_code == 200
    assert len(res_alpha_atk.json()["items"]) == 1
    alpha_atk = res_alpha_atk.json()["items"][0]
    assert alpha_atk["tenant_id"] == "tenant-alpha"
    assert "ssh" in alpha_atk["services_targeted"]
    assert "ftp" not in alpha_atk["services_targeted"]

    res_beta_atk = client.get("/api/attackers", headers={"X-Tenant-ID": "tenant-beta"})
    assert res_beta_atk.status_code == 200
    assert len(res_beta_atk.json()["items"]) == 1
    beta_atk = res_beta_atk.json()["items"][0]
    assert beta_atk["tenant_id"] == "tenant-beta"
    assert "ftp" in beta_atk["services_targeted"]
    assert "ssh" not in beta_atk["services_targeted"]


def test_cross_tenant_access_rejection(client):
    """Test that direct access to another tenant's records is rejected with 403 Forbidden."""
    # Create two tenants and insert records
    client.post("/api/tenants", json={"tenant_id": "tenant-owner", "name": "Owner Corp"})
    client.post("/api/tenants", json={"tenant_id": "tenant-intruder", "name": "Intruder Corp"})

    event_payload = {
        "event_id": "evt-private-100",
        "tenant_id": "tenant-owner",
        "asset_id": "ssh-priv-01",
        "event_type": "canary_triggered",
        "source_ip": "10.0.0.1",
        "source_port": 22,
        "username": "root",
        "protocol": "SSH",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "status": "triggered",
    }
    client.post("/api/events", json=event_payload)

    # Tenant Owner can access their own event
    res_owner = client.get("/api/events/evt-private-100", headers={"X-Tenant-ID": "tenant-owner"})
    assert res_owner.status_code == 200
    session_id = res_owner.json()["session_id"]

    # Tenant Intruder attempts to fetch Tenant Owner's event -> 403 Forbidden
    res_cross_event = client.get("/api/events/evt-private-100", headers={"X-Tenant-ID": "tenant-intruder"})
    assert res_cross_event.status_code == 403
    assert "Access denied" in res_cross_event.json()["detail"]

    # Tenant Intruder attempts to fetch Tenant Owner's session -> 403 Forbidden
    res_cross_session = client.get(f"/api/sessions/{session_id}", headers={"X-Tenant-ID": "tenant-intruder"})
    assert res_cross_session.status_code == 403
    assert "Access denied" in res_cross_session.json()["detail"]

    # Retrieve Tenant Owner's attacker profile
    res_owner_atk = client.get("/api/attackers", headers={"X-Tenant-ID": "tenant-owner"})
    assert res_owner_atk.status_code == 200
    owner_attacker_id = res_owner_atk.json()["items"][0]["attacker_id"]

    # Tenant Intruder attempts to fetch Tenant Owner's attacker profile -> 403 Forbidden
    res_cross_atk = client.get(f"/api/attackers/{owner_attacker_id}", headers={"X-Tenant-ID": "tenant-intruder"})
    assert res_cross_atk.status_code == 403
    assert "Access denied" in res_cross_atk.json()["detail"]


def test_data_access_layer_enforcement(test_db: Session):
    """Directly test the TenantDataAccess enforcement layer in Python."""
    # Seed events for two tenants
    evt_x = AttackEvent(
        event_id="evt-x-1",
        tenant_id="tenant-x",
        session_id="sess-x-1",
        source_ip="192.168.1.10",
        source_port=22,
        source_service="ssh",
        asset_id="ssh-001",
        event_type="auth_failure",
        severity="low",
        timestamp=datetime.now(timezone.utc),
    )
    evt_y = AttackEvent(
        event_id="evt-y-1",
        tenant_id="tenant-y",
        session_id="sess-y-1",
        source_ip="192.168.1.20",
        source_port=22,
        source_service="ssh",
        asset_id="ssh-002",
        event_type="auth_failure",
        severity="low",
        timestamp=datetime.now(timezone.utc),
    )
    test_db.add_all([evt_x, evt_y])
    test_db.commit()

    da_x = TenantDataAccess(test_db, tenant_id="tenant-x")
    da_y = TenantDataAccess(test_db, tenant_id="tenant-y")

    # 1. Tenant X fetches own event -> Success
    res = da_x.get_event("evt-x-1")
    assert res is not None
    assert res.event_id == "evt-x-1"

    # 2. Tenant X attempts to fetch Tenant Y's event -> Raises CrossTenantAccessDeniedException
    with pytest.raises(CrossTenantAccessDeniedException) as exc_info:
        da_x.get_event("evt-y-1")
    assert "Access denied" in str(exc_info.value)
    assert "tenant-y" in str(exc_info.value)

    # 3. List queries strictly scoped
    items_x, total_x = da_x.list_events()
    assert total_x == 1
    assert items_x[0].event_id == "evt-x-1"

    items_y, total_y = da_y.list_events()
    assert total_y == 1
    assert items_y[0].event_id == "evt-y-1"


def test_dashboard_analytics_tenant_scoping(client):
    """Test that dashboard statistics and activity metrics are strictly isolated by tenant."""
    # Seed events under tenant-dash-1 and tenant-dash-2
    for i in range(3):
        client.post("/api/events", json={
            "event_id": f"evt-dash1-{i}",
            "tenant_id": "tenant-dash-1",
            "asset_id": "ssh-dash-1",
            "event_type": "command_execution",
            "source_ip": f"10.0.1.{i}",
            "source_port": 22,
            "username": "admin",
            "protocol": "SSH",
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "status": "executed",
        })

    client.post("/api/events", json={
        "event_id": "evt-dash2-single",
        "tenant_id": "tenant-dash-2",
        "asset_id": "ftp-dash-2",
        "event_type": "auth_failure",
        "source_ip": "10.0.2.1",
        "source_port": 21,
        "username": "guest",
        "protocol": "FTP",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "status": "failed",
    })

    # Stats for tenant-dash-1: 3 events
    res1 = client.get("/api/dashboard/stats", headers={"X-Tenant-ID": "tenant-dash-1"})
    assert res1.status_code == 200
    data1 = res1.json()
    assert data1["total_events"] == 3
    assert data1["unique_attackers"] == 3

    # Stats for tenant-dash-2: 1 event
    res2 = client.get("/api/dashboard/stats", headers={"X-Tenant-ID": "tenant-dash-2"})
    assert res2.status_code == 200
    data2 = res2.json()
    assert data2["total_events"] == 1
    assert data2["unique_attackers"] == 1
