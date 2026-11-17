"""Tests for Honeytoken and Canary Trigger Integration (Person 1 - Task 1).

Verifies:
1. Triggering a honeytoken generates a normalized SecurityEvent.
2. Correct tenant and deceptive asset association.
3. Honeytoken events enter the existing collector and forwarding pipeline.
4. Successful backend delivery via EventForwarder.
5. Offline/failed delivery buffering in RetryQueue and recovery.
6. Duplicate trigger suppression and deduplication.
7. Sensitive data redaction (zero plaintext passwords in events/logs).
"""

import httpx
import pytest

from collector.daemon import CollectorDaemon
from collector.event_collector import EventCollector, global_collector
from collector.forwarder import EventForwarder
from collector.retry_queue import RetryQueue
from services.credentials.registry import (
    BaitCredential,
    CredentialRegistry,
    CredentialStatus,
)
from shared.config import settings
from shared.event_schema import EventStatus, EventType, SecurityEvent


@pytest.fixture(autouse=True)
def clean_collector():
    global_collector.clear()
    yield
    global_collector.clear()


@pytest.fixture
def isolated_env(tmp_path):
    """Provides isolated registry, retry queue, and forwarder."""
    creds_file = tmp_path / "test_creds.json"
    queue_db = tmp_path / "test_retry_queue.db"

    registry = CredentialRegistry(storage_file=creds_file)
    queue = RetryQueue(db_path=queue_db)

    delivered_batches = []

    def mock_post(client, url, json=None, headers=None):
        delivered_batches.append(json)
        return httpx.Response(200, json={"status": "accepted", "count": len(json)})

    forwarder = EventForwarder(
        api_url="http://mock-backend.internal/api/events",
        api_key="test-key-2026",
        retry_queue=queue,
    )

    daemon = CollectorDaemon(forwarder=forwarder, retry_queue=queue, flush_interval=0.05)

    return registry, queue, forwarder, daemon, delivered_batches, mock_post


def test_honeytoken_trigger_generates_normalized_event(isolated_env):
    """Test that triggering a honeytoken generates a valid normalized SecurityEvent."""
    registry, queue, forwarder, daemon, delivered, _ = isolated_env

    event = registry.trigger_honeytoken(
        honeytoken_id="htk-aws-key-001",
        asset_id="web-001",
        trigger_type="token_access",
        source_ip="198.51.100.42",
        source_port=44332,
        protocol="HTTP",
        tenant_id="tenant-apex-001",
        username="attacker_recon",
        severity="high",
        details={"path": "/.aws/credentials", "action": "canary_read"},
    )

    assert event is not None
    assert isinstance(event, SecurityEvent)
    assert event.honeytoken_id == "htk-aws-key-001"
    assert event.asset_id == "web-001"
    assert event.tenant_id == "tenant-apex-001"
    assert event.trigger_type == "token_access"
    assert event.severity == "high"
    assert event.source_ip == "198.51.100.42"
    assert event.source_port == 44332
    assert event.event_type == EventType.HONEYTOKEN_TRIGGER.value
    assert event.status == EventStatus.DETECTED.value
    assert event.source_service == "http"
    assert event.event_details["path"] == "/.aws/credentials"
    assert event.metadata["tenant_id"] == "tenant-apex-001"

    # Verify event was captured in global_collector
    assert global_collector.count() == 1
    collected = global_collector.get_all()[0]
    assert collected.event_id == event.event_id


def test_honeytoken_tenant_and_asset_association(isolated_env):
    """Verify that multiple tenants and assets remain strictly distinguished."""
    registry, queue, forwarder, daemon, delivered, _ = isolated_env

    # Tenant A
    evt_a = registry.trigger_honeytoken(
        honeytoken_id="htk-db-finance",
        asset_id="db-001",
        trigger_type="credential_use",
        source_ip="10.0.0.1",
        tenant_id="tenant-alpha",
    )

    # Tenant B
    evt_b = registry.trigger_honeytoken(
        honeytoken_id="htk-ssh-backup",
        asset_id="ssh-001",
        trigger_type="credential_use",
        source_ip="10.0.0.2",
        tenant_id="tenant-beta",
    )

    assert evt_a.tenant_id == "tenant-alpha"
    assert evt_a.asset_id == "db-001"
    assert evt_b.tenant_id == "tenant-beta"
    assert evt_b.asset_id == "ssh-001"
    assert global_collector.count() == 2


def test_canary_bait_credential_triggers_include_tenant_and_honeytoken(isolated_env):
    """Verify that evaluate_interaction populates tenant and honeytoken metadata."""
    registry, queue, forwarder, daemon, delivered, _ = isolated_env

    is_bait, canary_evt, reuse_evt = registry.evaluate_interaction(
        username="finance_admin",
        password_attempt="Finance@2026",
        target_asset="ssh-001",
        src_ip="203.0.113.15",
        protocol="SSH",
        tenant_id="tenant-apex-001",
    )

    assert is_bait is True
    assert canary_evt is not None
    assert canary_evt.tenant_id == "tenant-apex-001"
    assert canary_evt.honeytoken_id == "htk-finance_admin"
    assert canary_evt.trigger_type == "credential_use"
    assert canary_evt.severity == "critical"
    assert canary_evt.source_service == "ssh"
    assert canary_evt.metadata["canary_triggered"] is True
    assert canary_evt.metadata["tenant_id"] == "tenant-apex-001"


def test_cross_service_lateral_movement_honeytoken_enrichment(isolated_env):
    """Verify lateral reuse generates CREDENTIAL_REUSE with tenant and honeytoken details."""
    registry, queue, forwarder, daemon, delivered, _ = isolated_env

    # Origin asset is 'ssh-001', used on 'db-001'
    is_bait, canary_evt, reuse_evt = registry.evaluate_interaction(
        username="finance_admin",
        password_attempt="Finance@2026",
        target_asset="db-001",
        src_ip="198.51.100.99",
        protocol="DATABASE",
        tenant_id="tenant-apex-001",
    )

    assert is_bait is True
    assert canary_evt is not None
    assert reuse_evt is not None
    assert reuse_evt.tenant_id == "tenant-apex-001"
    assert reuse_evt.honeytoken_id == "htk-finance_admin"
    assert reuse_evt.trigger_type == "credential_reuse"
    assert reuse_evt.severity == "critical"
    assert reuse_evt.metadata["origin_asset"] == "ssh-001"
    assert reuse_evt.metadata["target_asset"] == "db-001"


def test_honeytoken_forwarding_pipeline_delivery(isolated_env, monkeypatch):
    """Test that honeytoken triggers flow through the daemon and forwarder into backend."""
    registry, queue, forwarder, daemon, delivered, mock_post = isolated_env
    monkeypatch.setattr(httpx.Client, "post", mock_post)

    # Generate honeytoken trigger
    registry.trigger_honeytoken(
        honeytoken_id="htk-decoy-config",
        asset_id="web-001",
        trigger_type="file_access",
        source_ip="192.0.2.10",
        tenant_id="tenant-apex-001",
        protocol="HTTP",
        details={"filename": "api_keys.json"},
    )

    assert global_collector.count() == 1

    # Run daemon flush cycle
    flushed = daemon.process_cycle()
    assert flushed == 1
    assert global_collector.count() == 0
    assert len(delivered) == 1

    batch = delivered[0]
    assert len(batch) == 1
    event_payload = batch[0]
    assert event_payload["honeytoken_id"] == "htk-decoy-config"
    assert event_payload["asset_id"] == "web-001"
    assert event_payload["tenant_id"] == "tenant-apex-001"
    assert event_payload["trigger_type"] == "file_access"


def test_honeytoken_failed_delivery_buffering_and_recovery(isolated_env, monkeypatch):
    """Test that failed backend delivery buffers into RetryQueue and recovers upon reconnect."""
    registry, queue, forwarder, daemon, delivered, mock_post = isolated_env

    # Simulate backend down (500 Internal Server Error)
    def failing_post(client, url, json=None, headers=None):
        return httpx.Response(500, text="Internal Server Error")

    monkeypatch.setattr(httpx.Client, "post", failing_post)

    evt = registry.trigger_honeytoken(
        honeytoken_id="htk-db-root-canary",
        asset_id="db-001",
        trigger_type="credential_use",
        source_ip="203.0.113.88",
        tenant_id="tenant-apex-001",
    )

    # Forward directly while backend is down
    success = forwarder.send_event(evt)
    assert success is False
    assert queue.count() == 1  # Buffered in SQLite RetryQueue

    # Now restore backend (200 OK)
    monkeypatch.setattr(httpx.Client, "post", mock_post)

    # Retry queue flush succeeds
    recovered = forwarder.flush_retry_queue()
    assert recovered == 1
    assert queue.count() == 0
    assert len(delivered) == 1
    assert delivered[0][0]["honeytoken_id"] == "htk-db-root-canary"


def test_honeytoken_duplicate_suppression(isolated_env):
    """Verify that duplicate triggers with same event_id are suppressed."""
    registry, queue, forwarder, daemon, delivered, _ = isolated_env

    explicit_id = "00000000-0000-0000-0000-000000000001"

    # First trigger
    evt1 = registry.trigger_honeytoken(
        honeytoken_id="htk-dup-test",
        asset_id="ssh-001",
        trigger_type="credential_use",
        source_ip="198.51.100.1",
        event_id=explicit_id,
    )
    assert global_collector.count() == 1

    # Second trigger with identical event_id
    evt2 = SecurityEvent(
        event_id=explicit_id,
        asset_id="ssh-001",
        event_type=EventType.HONEYTOKEN_TRIGGER.value,
        source_ip="198.51.100.1",
        protocol="SSH",
        status=EventStatus.DETECTED.value,
        honeytoken_id="htk-dup-test",
        trigger_type="credential_use",
    )
    added = global_collector.collect(evt2)
    assert added is False
    assert global_collector.count() == 1  # Duplicate suppressed


def test_honeytoken_sensitive_credential_redaction(isolated_env):
    """Verify that plaintext passwords in trigger details are never retained."""
    registry, queue, forwarder, daemon, delivered, _ = isolated_env

    evt = registry.trigger_honeytoken(
        honeytoken_id="htk-secret-env",
        asset_id="web-001",
        trigger_type="credential_use",
        source_ip="192.168.1.50",
        details={
            "attempted_password": "SuperSecretPassword123!",
            "cloud_secret_key": "AKIAIOSFODNN7EXAMPLE",
            "file": ".env.production",
        },
    )

    # Verify no raw passwords/secrets in event_details or metadata
    details_str = str(evt.event_details)
    metadata_str = str(evt.metadata)

    assert "SuperSecretPassword123!" not in details_str
    assert "SuperSecretPassword123!" not in metadata_str
    assert "AKIAIOSFODNN7EXAMPLE" not in details_str
    assert "AKIAIOSFODNN7EXAMPLE" not in metadata_str

    assert evt.event_details.get("attempted_password_length") == len("SuperSecretPassword123!")
    assert evt.event_details.get("cloud_secret_key_length") == len("AKIAIOSFODNN7EXAMPLE")
    assert evt.event_details.get("file") == ".env.production"
