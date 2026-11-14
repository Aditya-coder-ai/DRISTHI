"""Unit tests for evidence-based MITRE ATT&CK mapping engine."""

from backend.app.schemas.event import AttackEventCreate
from backend.app.services.mitre_service import MitreService


def test_classify_password_guessing():
    evt = AttackEventCreate(
        event_id="m-1",
        source_ip="10.10.10.10",
        source_service="ssh",
        asset_id="ssh-001",
        event_type="login_failed",
        username="admin",
        status="failed",
        timestamp="2026-11-14T04:00:00Z",
    )
    mappings = MitreService.classify_event(evt)
    technique_ids = {m.technique_id for m in mappings}
    assert "T1110.001" in technique_ids

    mapping = next(m for m in mappings if m.technique_id == "T1110.001")
    assert "admin" in mapping.evidence
    assert mapping.confidence >= 0.90


def test_classify_bait_credential_trigger():
    evt = AttackEventCreate(
        event_id="m-2",
        source_ip="10.10.10.10",
        source_service="ssh",
        asset_id="ssh-001",
        event_type="bait_credential_trigger",
        username="finance_admin",
        status="detected",
        timestamp="2026-11-14T04:05:00Z",
        metadata={"bait_credential_triggered": True},
    )
    mappings = MitreService.classify_event(evt)
    technique_ids = {m.technique_id for m in mappings}
    assert "T1078" in technique_ids


def test_classify_command_execution():
    evt = AttackEventCreate(
        event_id="m-3",
        source_ip="10.10.10.10",
        source_service="ssh",
        asset_id="ssh-001",
        event_type="command_execution",
        status="executed",
        timestamp="2026-11-14T04:10:00Z",
        activity={"command": "uname -a"},
    )
    mappings = MitreService.classify_event(evt)
    technique_ids = {m.technique_id for m in mappings}
    assert "T1059.004" in technique_ids
    assert "T1082" in technique_ids


def test_classify_exfiltration():
    evt = AttackEventCreate(
        event_id="m-4",
        source_ip="10.10.10.10",
        source_service="ftp",
        asset_id="ftp-001",
        event_type="file_download",
        status="success",
        timestamp="2026-11-14T04:15:00Z",
        activity={"filename": "backup.zip"},
    )
    mappings = MitreService.classify_event(evt)
    technique_ids = {m.technique_id for m in mappings}
    assert "T1048" in technique_ids

