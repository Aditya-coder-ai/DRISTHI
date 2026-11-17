"""Tests for Deceptive Asset Registry and Additional Deceptive Asset Support (Person 1 - Task 2).

Verifies:
1. Default deceptive assets (honeypots, cloud credentials, decoy files, fake endpoints) seeded.
2. Registration of new deceptive assets (API keys, env files, connection strings, documents).
3. Retrieval filtering by tenant, asset type, and service.
4. Access triggering produces normalized SecurityEvent records.
5. Integration with event collector, daemon, and forwarder pipeline.
6. Plaintext password and secret redaction.
7. Validation of asset ID uniqueness and non-empty fields.
"""

import httpx
import pytest

from collector.daemon import CollectorDaemon
from collector.event_collector import global_collector
from collector.forwarder import EventForwarder
from collector.retry_queue import RetryQueue
from shared.asset_registry import (
    AssetRegistry,
    AssetStatus,
    AssetType,
    DeceptiveAsset,
)
from shared.config import settings
from shared.event_schema import EventStatus, EventType, SecurityEvent


@pytest.fixture(autouse=True)
def clean_collector():
    global_collector.clear()
    yield
    global_collector.clear()


@pytest.fixture
def isolated_asset_env(tmp_path):
    """Provides isolated registry, retry queue, and forwarder."""
    queue_db = tmp_path / "test_asset_retry.db"
    queue = RetryQueue(db_path=queue_db)
    registry = AssetRegistry(tenant_id="tenant-apex-001")

    delivered_batches = []

    def mock_post(client, url, json=None, headers=None):
        delivered_batches.append(json)
        return httpx.Response(200, json={"status": "accepted", "count": len(json)})

    forwarder = EventForwarder(
        api_url="http://mock-backend.corp/api/events",
        api_key="test-key",
        retry_queue=queue,
    )
    daemon = CollectorDaemon(forwarder=forwarder, retry_queue=queue, flush_interval=0.05)

    return registry, queue, forwarder, daemon, delivered_batches, mock_post


def test_default_assets_seeded_properly(isolated_asset_env):
    """Verify standard honeypots and decoy assets are pre-registered with correct metadata."""
    registry, queue, forwarder, daemon, delivered, _ = isolated_asset_env

    assert registry.count() >= 9

    # Primary Honeypots
    ssh = registry.get("ssh-001")
    assert ssh is not None
    assert ssh.asset_type == AssetType.HONEYPOT.value
    assert ssh.service_type == "ssh"
    assert ssh.tenant_id == "tenant-apex-001"
    assert ssh.status == AssetStatus.ACTIVE.value

    web = registry.get("web-001")
    assert web is not None
    assert web.asset_type == AssetType.HONEYPOT.value
    assert web.service_type == "web"

    # Decoy Assets
    aws_key = registry.get("apikey-aws-001")
    assert aws_key is not None
    assert aws_key.asset_type == AssetType.API_KEY.value
    assert "AKIAIOSFODNN7EXAMPLE" in aws_key.fictional_payload["access_key_id"]

    db_str = registry.get("config-db-001")
    assert db_str is not None
    assert db_str.asset_type == AssetType.DB_CONNECTION_STRING.value
    assert "postgresql://" in db_str.fictional_payload["connection_uri"]


def test_register_new_custom_deceptive_assets(isolated_asset_env):
    """Verify registering various new deceptive asset types."""
    registry, queue, forwarder, daemon, delivered, _ = isolated_asset_env

    # 1. Fake Azure API Key
    azure_asset = DeceptiveAsset(
        asset_id="apikey-azure-001",
        tenant_id="tenant-apex-001",
        asset_type=AssetType.API_KEY.value,
        asset_name="Azure KeyVault Decoy Secret",
        service_type="azure",
        deployment_location="web:/configuration/azure.json",
        fictional_payload={"vault_uri": "https://apex-corp-vault.vault.azure.net/"},
    )
    registry.register(azure_asset)

    # 2. Fake Environment File
    env_asset = DeceptiveAsset(
        asset_id="env-staging-001",
        tenant_id="tenant-apex-001",
        asset_type=AssetType.ENV_FILE.value,
        asset_name="Staging Environment Dotenv File",
        service_type="web",
        deployment_location="ftp:/backups/env/.env.staging",
    )
    registry.register(env_asset)

    # 3. Decoy Internal Endpoint
    endpoint_asset = DeceptiveAsset(
        asset_id="endpoint-k8s-001",
        tenant_id="tenant-apex-001",
        asset_type=AssetType.SERVICE_ENDPOINT.value,
        asset_name="Kubernetes Internal Dashboard Decoy",
        service_type="web",
        deployment_location="http://k8s-admin.corp.internal:8443",
    )
    registry.register(endpoint_asset)

    assert registry.get("apikey-azure-001") is not None
    assert registry.get("env-staging-001") is not None
    assert registry.get("endpoint-k8s-001") is not None


def test_query_assets_by_tenant_type_and_service(isolated_asset_env):
    """Verify querying assets filtered by tenant, type, or service."""
    registry, queue, forwarder, daemon, delivered, _ = isolated_asset_env

    # Filter by tenant
    tenant_assets = registry.get_by_tenant("tenant-apex-001")
    assert len(tenant_assets) >= 9

    # Filter by asset type
    honeypots = registry.get_by_type(AssetType.HONEYPOT.value)
    assert len(honeypots) == 4
    hp_ids = {h.asset_id for h in honeypots}
    assert hp_ids == {"ssh-001", "ftp-001", "web-001", "db-001"}

    # Filter by service type
    web_assets = registry.get_by_service("web")
    assert len(web_assets) >= 2


def test_trigger_asset_access_generates_normalized_event(isolated_asset_env):
    """Verify that triggering an asset generates a valid SecurityEvent and updates status."""
    registry, queue, forwarder, daemon, delivered, _ = isolated_asset_env

    event = registry.trigger_asset_access(
        asset_id="apikey-aws-001",
        source_ip="198.51.100.77",
        source_port=54321,
        username="attacker_scanner",
        trigger_type="key_leak_probe",
        severity="critical",
        details={"path": "/configuration/aws_keys.env", "tool": "git-hound"},
    )

    assert event is not None
    assert event.asset_id == "apikey-aws-001"
    assert event.tenant_id == "tenant-apex-001"
    assert event.honeytoken_id == "apikey-aws-001"
    assert event.trigger_type == "key_leak_probe"
    assert event.severity == "critical"
    assert event.source_ip == "198.51.100.77"
    assert event.source_service == "aws"
    assert event.status == EventStatus.DETECTED.value

    # Check asset status in registry updated to TRIGGERED
    asset = registry.get("apikey-aws-001")
    assert asset.status == AssetStatus.TRIGGERED.value

    # Verify event collected in pipeline
    assert global_collector.count() == 1


def test_trigger_asset_access_pipeline_delivery(isolated_asset_env, monkeypatch):
    """Verify asset trigger events flow through daemon and forwarder into central backend."""
    registry, queue, forwarder, daemon, delivered, mock_post = isolated_asset_env
    monkeypatch.setattr(httpx.Client, "post", mock_post)

    registry.trigger_asset_access(
        asset_id="doc-exec-comp-001",
        source_ip="203.0.113.33",
        trigger_type="document_download",
        details={"file": "executive_compensation_q4_2025.pdf"},
    )

    assert global_collector.count() == 1

    # Flush daemon cycle
    flushed = daemon.process_cycle()
    assert flushed == 1
    assert global_collector.count() == 0
    assert len(delivered) == 1

    batch = delivered[0]
    assert len(batch) == 1
    item = batch[0]
    assert item["asset_id"] == "doc-exec-comp-001"
    assert item["tenant_id"] == "tenant-apex-001"
    assert item["trigger_type"] == "document_download"


def test_security_requirements_fictional_data_and_redaction(isolated_asset_env):
    """Verify that credentials in details are sanitized and fictional data rules are met."""
    registry, queue, forwarder, daemon, delivered, _ = isolated_asset_env

    event = registry.trigger_asset_access(
        asset_id="config-db-001",
        source_ip="192.0.2.88",
        trigger_type="credential_extraction",
        details={
            "database_password": "PlaintextPasswordShouldBeRedacted",
            "api_secret": "SuperSecretKey99",
            "query": "SELECT * FROM users",
        },
    )

    event_str = event.model_dump_json()
    assert "PlaintextPasswordShouldBeRedacted" not in event_str
    assert "SuperSecretKey99" not in event_str

    assert event.event_details.get("database_password_length") == len("PlaintextPasswordShouldBeRedacted")
    assert event.event_details.get("api_secret_length") == len("SuperSecretKey99")
    assert event.event_details.get("query") == "SELECT * FROM users"


def test_asset_uniqueness_and_validation(isolated_asset_env):
    """Verify asset ID uniqueness and non-empty field validation."""
    registry, queue, forwarder, daemon, delivered, _ = isolated_asset_env

    # 1. Duplicate asset_id rejected
    dup_asset = DeceptiveAsset(
        asset_id="ssh-001",  # Already exists
        tenant_id="tenant-apex-001",
        asset_type=AssetType.HONEYPOT.value,
        asset_name="Duplicate SSH",
        service_type="ssh",
        deployment_location="network:0.0.0.0:2222",
    )
    with pytest.raises(ValueError, match="already registered"):
        registry.register(dup_asset)

    # 2. Blank asset_id rejected
    with pytest.raises(ValueError, match="Asset ID cannot be empty"):
        registry.register(
            DeceptiveAsset(
                asset_id="",
                tenant_id="tenant-apex-001",
                asset_type="api_key",
                asset_name="Blank",
                service_type="ssh",
                deployment_location="loc",
            )
        )

    # 3. Blank tenant_id rejected
    with pytest.raises(ValueError, match="Tenant ID cannot be empty"):
        registry.register(
            DeceptiveAsset(
                asset_id="new-001",
                tenant_id="",
                asset_type="api_key",
                asset_name="No Tenant",
                service_type="ssh",
                deployment_location="loc",
            )
        )

    # 4. Triggering non-existent asset raises ValueError
    with pytest.raises(ValueError, match="not found in registry"):
        registry.trigger_asset_access(
            asset_id="non-existent-999",
            source_ip="1.2.3.4",
        )
