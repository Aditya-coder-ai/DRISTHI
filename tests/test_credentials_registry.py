"""Tests for Centralized Dynamic Bait Credentials Registry and Canary Detection."""

import pytest

from collector.event_collector import global_collector
from services.credentials.registry import (
    BaitCredential,
    CredentialRegistry,
    CredentialStatus,
)
from shared.event_schema import EventStatus, EventType


@pytest.fixture(autouse=True)
def clean_test_collector():
    global_collector.clear()
    yield
    global_collector.clear()


@pytest.fixture
def temp_registry(tmp_path):
    """Create isolated registry using temporary storage."""
    reg_file = tmp_path / "test_creds.json"
    registry = CredentialRegistry(storage_file=reg_file)
    return registry


def test_registry_seed_credentials_loaded(temp_registry):
    """Verify standard bait accounts are initialized with SHA-256 hashes."""
    assert temp_registry.count() >= 3

    # Check finance_admin
    cred = temp_registry._credentials.get("finance_admin")
    assert cred is not None
    assert cred.origin_asset == "ssh-001"
    assert cred.status == CredentialStatus.ACTIVE
    assert cred.verify_password("Finance@2026") is True
    assert cred.verify_password("WrongPassword") is False


def test_registry_registration(temp_registry):
    """Verify registering a new decoy credential."""
    cred = temp_registry.register(
        username="audit_operator",
        password="Audit@2026Secure",
        origin_asset="web-001",
        planted_locations=["web:/configuration/audit.cfg"],
        description="Bait credential for compliance auditor",
    )
    assert cred.username == "audit_operator"
    assert cred.verify_password("Audit@2026Secure") is True
    assert temp_registry.count() >= 4


def test_canary_trigger_on_origin_asset(temp_registry):
    """Verify authenticating with bait credential on origin asset emits CANARY_TRIGGERED."""
    is_bait, canary_evt, reuse_evt = temp_registry.evaluate_interaction(
        username="finance_admin",
        password_attempt="Finance@2026",
        target_asset="ssh-001",
        src_ip="203.0.113.50",
        protocol="SSH",
    )
    assert is_bait is True
    assert canary_evt is not None
    assert canary_evt.event_type == EventType.CANARY_TRIGGERED.value
    assert canary_evt.metadata["alert_priority"] == "CRITICAL"
    assert canary_evt.metadata["origin_asset"] == "ssh-001"
    # No reuse event since origin == target
    assert reuse_evt is None

    # Check credential status updated
    cred = temp_registry._credentials["finance_admin"]
    assert cred.status == CredentialStatus.TRIGGERED
    assert cred.trigger_count == 1


def test_cross_service_lateral_movement_reuse_detection(temp_registry):
    """Verify authenticating with a bait credential on a DIFFERENT asset emits CREDENTIAL_REUSE."""
    # Credential origin is 'ssh-001', but used on 'db-001'
    is_bait, canary_evt, reuse_evt = temp_registry.evaluate_interaction(
        username="finance_admin",
        password_attempt="Finance@2026",
        target_asset="db-001",
        src_ip="198.51.100.22",
        protocol="DATABASE",
    )
    assert is_bait is True
    assert canary_evt is not None
    assert reuse_evt is not None

    # Validate CREDENTIAL_REUSE event
    assert reuse_evt.event_type == EventType.CREDENTIAL_REUSE.value
    assert reuse_evt.status == EventStatus.DETECTED.value
    assert reuse_evt.metadata["alert_priority"] == "CRITICAL"
    assert reuse_evt.metadata["origin_asset"] == "ssh-001"
    assert reuse_evt.metadata["target_asset"] == "db-001"
    assert "reused on db-001" in reuse_evt.metadata["indicator"]


def test_credential_rotation(temp_registry):
    """Verify rotating credential updates previous status and activates new password."""
    cred = temp_registry._credentials["backup_user"]
    orig_hash = cred.password_hash

    rotated = temp_registry.rotate("backup_user", new_password="NewBackupPass@2026")
    assert rotated is not None
    assert rotated.verify_password("NewBackupPass@2026") is True
    assert rotated.password_hash != orig_hash
