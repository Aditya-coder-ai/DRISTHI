"""Integration tests for Multi-Tenant Isolation of Integration Configurations."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.app.core.exceptions import CrossTenantAccessDeniedException
from backend.app.models.tenant import Tenant
from backend.app.schemas.integration import IntegrationCreate, IntegrationUpdate
from backend.app.services.tenant_data_access import TenantDataAccess


TENANT_A = "tenant-apex-001"
TENANT_B = "tenant-cyber-002"


@pytest.fixture(autouse=True)
def setup_tenants(test_db: Session):
    """Seed test tenants."""
    t1 = test_db.query(Tenant).filter(Tenant.tenant_id == TENANT_A).first()
    if not t1:
        test_db.add(Tenant(tenant_id=TENANT_A, name="Apex Tenant", is_active=True))

    t2 = test_db.query(Tenant).filter(Tenant.tenant_id == TENANT_B).first()
    if not t2:
        test_db.add(Tenant(tenant_id=TENANT_B, name="Cyber Tenant", is_active=True))

    test_db.commit()


def test_integration_listing_isolated_by_tenant(client: TestClient):
    """Integrations registered in Tenant A must never appear in Tenant B's listing."""
    # Tenant A creates integration
    res_a = client.post(
        "/api/integrations",
        headers={"X-Tenant-ID": TENANT_A},
        json={
            "integration_id": "intg-tenant-a-wh",
            "name": "Tenant A Secret Webhook",
            "integration_type": "webhook",
            "config_metadata": {"url": "https://tenant-a.internal/hook"},
            "secret": "tenant_a_super_secret_token",
        },
    )
    assert res_a.status_code == 201

    # Tenant B creates integration
    res_b = client.post(
        "/api/integrations",
        headers={"X-Tenant-ID": TENANT_B},
        json={
            "integration_id": "intg-tenant-b-siem",
            "name": "Tenant B SIEM",
            "integration_type": "siem",
            "config_metadata": {"host": "siem.tenant-b.internal", "port": 514},
        },
    )
    assert res_b.status_code == 201

    # Tenant A list
    list_a = client.get("/api/integrations", headers={"X-Tenant-ID": TENANT_A})
    assert list_a.status_code == 200
    ids_a = [it["integration_id"] for it in list_a.json()["items"]]
    assert "intg-tenant-a-wh" in ids_a
    assert "intg-tenant-b-siem" not in ids_a

    # Tenant B list
    list_b = client.get("/api/integrations", headers={"X-Tenant-ID": TENANT_B})
    assert list_b.status_code == 200
    ids_b = [it["integration_id"] for it in list_b.json()["items"]]
    assert "intg-tenant-b-siem" in ids_b
    assert "intg-tenant-a-wh" not in ids_b


def test_cross_tenant_integration_operations_rejected(client: TestClient):
    """Tenant B cannot read, update, toggle, delete, or validate Tenant A's integration."""
    # Tenant A creates private integration
    client.post(
        "/api/integrations",
        headers={"X-Tenant-ID": TENANT_A},
        json={
            "integration_id": "intg-private-a",
            "name": "Private A SIEM",
            "integration_type": "siem",
            "config_metadata": {"host": "siem-a.internal"},
            "secret": "super_secret_a_token",
        },
    )

    # 1. Cross-tenant GET -> 403 Forbidden
    res_get = client.get("/api/integrations/intg-private-a", headers={"X-Tenant-ID": TENANT_B})
    assert res_get.status_code == 403
    assert "access denied" in res_get.json()["detail"].lower()

    # 2. Cross-tenant PUT -> 403 Forbidden
    res_put = client.put(
        "/api/integrations/intg-private-a",
        headers={"X-Tenant-ID": TENANT_B},
        json={"name": "Hijacked Name"},
    )
    assert res_put.status_code == 403
    assert "access denied" in res_put.json()["detail"].lower()

    # 3. Cross-tenant TOGGLE -> 403 Forbidden
    res_toggle = client.patch(
        "/api/integrations/intg-private-a/toggle",
        headers={"X-Tenant-ID": TENANT_B},
    )
    assert res_toggle.status_code == 403
    assert "access denied" in res_toggle.json()["detail"].lower()

    # 4. Cross-tenant VALIDATE -> 403 Forbidden
    res_val = client.post(
        "/api/integrations/intg-private-a/validate",
        headers={"X-Tenant-ID": TENANT_B},
    )
    assert res_val.status_code == 403
    assert "access denied" in res_val.json()["detail"].lower()

    # 5. Cross-tenant DELETE -> 403 Forbidden
    res_del = client.delete(
        "/api/integrations/intg-private-a",
        headers={"X-Tenant-ID": TENANT_B},
    )
    assert res_del.status_code == 403
    assert "access denied" in res_del.json()["detail"].lower()


def test_tenant_data_access_layer_direct_isolation(test_db: Session):
    """Direct TenantDataAccess queries must strictly enforce tenant boundaries."""
    da_a = TenantDataAccess(test_db, TENANT_A)
    da_b = TenantDataAccess(test_db, TENANT_B)

    # Tenant A creates integration
    intg_a = da_a.create_integration(IntegrationCreate(
        integration_id="direct-intg-a",
        name="Direct Tenant A Hook",
        integration_type="webhook",
        config_metadata={"url": "https://hook.internal"},
        secret="direct_secret_12345",
    ))
    assert intg_a.integration_id == "direct-intg-a"

    # da_b lookups must raise CrossTenantAccessDeniedException
    with pytest.raises(CrossTenantAccessDeniedException):
        da_b.get_integration("direct-intg-a")

    with pytest.raises(CrossTenantAccessDeniedException):
        da_b.update_integration("direct-intg-a", IntegrationUpdate(name="Tampered"))

    with pytest.raises(CrossTenantAccessDeniedException):
        da_b.toggle_integration("direct-intg-a")

    with pytest.raises(CrossTenantAccessDeniedException):
        da_b.validate_integration("direct-intg-a")

    with pytest.raises(CrossTenantAccessDeniedException):
        da_b.delete_integration("direct-intg-a")
