"""Tests for Unique Asset ID & Multi-Tenant Isolation (Person 1 - Task 3).

Verifies:
1. All deceptive assets have unique stable IDs and belong to a valid tenant.
2. Event schema validation prevents blank asset IDs and blank tenant IDs.
3. Event normalization through SSH, FTP, Web, and DB adapters inherits tenant ID.
4. Prevention of cross-tenant event leakage and strict tenant event isolation.
5. Cross-tenant asset access attempts are rejected.
6. Verification of asset ownership and event tenant integrity.
"""

import pytest

from collector.event_collector import global_collector
from collector.normalizer import EventNormalizer
from services.database.db_event_adapter import DatabaseEventAdapter
from services.ftp.ftp_event_adapter import FTPEventAdapter
from services.ssh.ssh_event_adapter import CowrieSSHAdapter
from services.web.web_event_adapter import WebEventAdapter
from shared.asset_registry import (
    AssetRegistry,
    AssetStatus,
    AssetType,
    DeceptiveAsset,
)
from shared.config import settings
from shared.event_schema import EventStatus, EventType, ProtocolType, SecurityEvent


@pytest.fixture(autouse=True)
def clean_collector():
    global_collector.clear()
    yield
    global_collector.clear()


@pytest.fixture
def multi_tenant_registry():
    """Create an isolated AssetRegistry with multi-tenant assets."""
    registry = AssetRegistry(tenant_id="tenant-alpha")

    # Add assets for Tenant Beta
    registry.register(
        DeceptiveAsset(
            asset_id="ssh-beta-001",
            tenant_id="tenant-beta",
            asset_type=AssetType.HONEYPOT.value,
            asset_name="Beta Corp SSH Honeybox",
            service_type="ssh",
            deployment_location="network:10.20.0.1:2222",
        )
    )
    registry.register(
        DeceptiveAsset(
            asset_id="apikey-beta-001",
            tenant_id="tenant-beta",
            asset_type=AssetType.API_KEY.value,
            asset_name="Beta Cloud API Key",
            service_type="aws",
            deployment_location="web:/config/keys.json",
        )
    )
    return registry


def test_existing_honeypots_have_valid_asset_id_and_tenant():
    """Verify core honeypots have stable asset IDs and valid tenant associations."""
    reg = AssetRegistry()

    expected_assets = ["ssh-001", "ftp-001", "web-001", "db-001"]
    for aid in expected_assets:
        asset = reg.get(aid)
        assert asset is not None, f"Asset {aid} missing from registry"
        assert asset.asset_id == aid
        assert asset.tenant_id == settings.DEFAULT_TENANT_ID
        assert len(asset.tenant_id.strip()) > 0
        assert asset.status == AssetStatus.ACTIVE.value


def test_asset_creation_validation(multi_tenant_registry):
    """Verify validation on deceptive asset creation."""
    reg = multi_tenant_registry

    # 1. Blank asset_id is rejected
    with pytest.raises(ValueError, match="Asset ID cannot be empty"):
        reg.register(
            DeceptiveAsset(
                asset_id="   ",
                tenant_id="tenant-alpha",
                asset_type="api_key",
                asset_name="Bad Asset",
                service_type="aws",
                deployment_location="loc",
            )
        )

    # 2. Blank tenant_id is rejected
    with pytest.raises(ValueError, match="Tenant ID cannot be empty"):
        reg.register(
            DeceptiveAsset(
                asset_id="valid-id-001",
                tenant_id="",
                asset_type="api_key",
                asset_name="Bad Asset",
                service_type="aws",
                deployment_location="loc",
            )
        )

    # 3. Duplicate asset_id across or within tenants is rejected
    with pytest.raises(ValueError, match="already registered"):
        reg.register(
            DeceptiveAsset(
                asset_id="ssh-beta-001",  # already exists in tenant-beta
                tenant_id="tenant-alpha",  # trying to register under tenant-alpha
                asset_type="honeypot",
                asset_name="Duplicate ID Attempt",
                service_type="ssh",
                deployment_location="loc",
            )
        )


def test_security_event_schema_tenant_validation():
    """Verify SecurityEvent enforces non-blank asset_id and auto-populates/validates tenant_id."""
    # 1. Blank asset_id rejected
    with pytest.raises(ValueError, match="asset_id cannot be empty or blank"):
        SecurityEvent(
            asset_id="",
            event_type="test",
            source_ip="127.0.0.1",
            protocol="SSH",
            status="attempt",
        )

    # 2. Blank tenant_id rejected
    with pytest.raises(ValueError, match="tenant_id cannot be empty or blank"):
        SecurityEvent(
            asset_id="ssh-001",
            tenant_id="   ",
            event_type="test",
            source_ip="127.0.0.1",
            protocol="SSH",
            status="attempt",
        )

    # 3. Omitted tenant_id defaults to settings.DEFAULT_TENANT_ID
    evt = SecurityEvent(
        asset_id="ssh-001",
        event_type="test",
        source_ip="127.0.0.1",
        protocol="SSH",
        status="attempt",
    )
    assert evt.tenant_id == settings.DEFAULT_TENANT_ID


def test_all_service_adapters_preserve_tenant_id():
    """Verify that SSH, FTP, Web, and DB adapters properly assign and propagate tenant_id."""
    custom_tenant = "tenant-isolated-123"

    # 1. SSH Adapter
    ssh_raw = {"eventid": "cowrie.login.failed", "src_ip": "10.0.0.1", "username": "root"}
    ssh_evt = CowrieSSHAdapter.normalize(ssh_raw, asset_id="ssh-custom", tenant_id=custom_tenant)
    assert ssh_evt is not None
    assert ssh_evt.tenant_id == custom_tenant
    assert ssh_evt.asset_id == "ssh-custom"
    assert ssh_evt.metadata["tenant_id"] == custom_tenant

    # 2. FTP Adapter
    ftp_raw = {"eventid": "ftp.login.failed", "src_ip": "10.0.0.2", "username": "ftpuser"}
    ftp_evt = FTPEventAdapter.normalize(ftp_raw, asset_id="ftp-custom", tenant_id=custom_tenant)
    assert ftp_evt is not None
    assert ftp_evt.tenant_id == custom_tenant
    assert ftp_evt.asset_id == "ftp-custom"
    assert ftp_evt.metadata["tenant_id"] == custom_tenant

    # 3. Web Adapter
    web_raw = {"eventid": "web.login.failed", "src_ip": "10.0.0.3", "username": "admin"}
    web_evt = WebEventAdapter.normalize(web_raw, asset_id="web-custom", tenant_id=custom_tenant)
    assert web_evt is not None
    assert web_evt.tenant_id == custom_tenant
    assert web_evt.asset_id == "web-custom"
    assert web_evt.metadata["tenant_id"] == custom_tenant

    # 4. Database Adapter
    db_raw = {"eventid": "db.login.failed", "src_ip": "10.0.0.4", "username": "sa"}
    db_evt = DatabaseEventAdapter.normalize(db_raw, asset_id="db-custom", tenant_id=custom_tenant)
    assert db_evt is not None
    assert db_evt.tenant_id == custom_tenant
    assert db_evt.asset_id == "db-custom"
    assert db_evt.metadata["tenant_id"] == custom_tenant

    # 5. Normalizer Facade
    facade_evt = EventNormalizer.normalize(
        ssh_raw, protocol=ProtocolType.SSH.value, asset_id="ssh-001", tenant_id=custom_tenant
    )
    assert facade_evt is not None
    assert facade_evt.tenant_id == custom_tenant


def test_cross_tenant_event_isolation(multi_tenant_registry):
    """Verify that multi-tenant events are strictly partitioned and cannot leak across tenants."""
    reg = multi_tenant_registry

    # Generate events for Tenant Alpha
    evt_a1 = reg.trigger_asset_access(
        asset_id="ssh-001",  # belongs to tenant-alpha
        source_ip="192.168.1.10",
        tenant_id="tenant-alpha",
    )
    evt_a2 = reg.trigger_asset_access(
        asset_id="web-001",  # belongs to tenant-alpha
        source_ip="192.168.1.11",
        tenant_id="tenant-alpha",
    )

    # Generate events for Tenant Beta
    evt_b1 = reg.trigger_asset_access(
        asset_id="ssh-beta-001",  # belongs to tenant-beta
        source_ip="10.20.0.50",
        tenant_id="tenant-beta",
    )

    all_events = [evt_a1, evt_a2, evt_b1]

    # Filter for Tenant Alpha
    alpha_events = reg.filter_events_by_tenant(all_events, tenant_id="tenant-alpha")
    assert len(alpha_events) == 2
    assert all(e.tenant_id == "tenant-alpha" for e in alpha_events)
    assert not any(e.asset_id == "ssh-beta-001" for e in alpha_events)

    # Filter for Tenant Beta
    beta_events = reg.filter_events_by_tenant(all_events, tenant_id="tenant-beta")
    assert len(beta_events) == 1
    assert beta_events[0].tenant_id == "tenant-beta"
    assert beta_events[0].asset_id == "ssh-beta-001"

    # Filter for non-existent Tenant Gamma returns empty
    gamma_events = reg.filter_events_by_tenant(all_events, tenant_id="tenant-gamma")
    assert len(gamma_events) == 0


def test_cross_tenant_asset_access_rejected(multi_tenant_registry):
    """Verify that attempting to trigger an asset using the wrong tenant ID raises an exception."""
    reg = multi_tenant_registry

    # Asset 'ssh-beta-001' belongs to 'tenant-beta'
    # Triggering with 'tenant-alpha' must fail
    with pytest.raises(ValueError, match="Cross-tenant mismatch"):
        reg.trigger_asset_access(
            asset_id="ssh-beta-001",
            source_ip="10.20.0.99",
            tenant_id="tenant-alpha",  # Wrong tenant!
        )


def test_asset_ownership_verification(multi_tenant_registry):
    """Verify asset ownership verification helper."""
    reg = multi_tenant_registry

    assert reg.validate_asset_ownership("ssh-beta-001", "tenant-beta") is True
    assert reg.validate_asset_ownership("ssh-beta-001", "tenant-alpha") is False
    assert reg.validate_asset_ownership("ssh-001", "tenant-alpha") is True
    assert reg.validate_asset_ownership("non-existent", "tenant-alpha") is False


def test_event_tenant_isolation_validation(multi_tenant_registry):
    """Verify validation of event tenant isolation."""
    reg = multi_tenant_registry

    valid_event = SecurityEvent(
        asset_id="ssh-001",
        tenant_id="tenant-alpha",
        event_type="test",
        source_ip="127.0.0.1",
        protocol="SSH",
        status="attempt",
    )
    assert reg.validate_event_tenant_isolation(valid_event, "tenant-alpha") is True
    assert reg.validate_event_tenant_isolation(valid_event, "tenant-beta") is False

    # Forged event where event.tenant_id is tenant-beta but asset_id belongs to tenant-alpha
    forged_event = SecurityEvent(
        asset_id="ssh-001",  # belongs to tenant-alpha
        tenant_id="tenant-beta",  # spoofed
        event_type="test",
        source_ip="127.0.0.1",
        protocol="SSH",
        status="attempt",
    )
    assert reg.validate_event_tenant_isolation(forged_event, "tenant-beta") is False
