"""Integration tests for SQLAlchemy database persistence and relationships."""

from datetime import datetime, timezone
from backend.app.models.attacker import AttackerProfile
from backend.app.models.event import AttackEvent
from backend.app.models.mitre import MitreMapping
from backend.app.models.session import AttackerSession


def test_persist_attack_event_and_session(test_db):
    now = datetime.now(timezone.utc)

    # 1. Profile
    profile = AttackerProfile(
        attacker_id="atk-test-1",
        source_ip="192.0.2.100",
        first_seen=now,
        last_seen=now,
        total_events=1,
        total_sessions=1,
    )
    test_db.add(profile)
    test_db.flush()

    # 2. Session
    session = AttackerSession(
        session_id="sess-test-1",
        attacker_id=profile.attacker_id,
        source_ip="192.0.2.100",
        first_seen=now,
        last_seen=now,
        services_accessed=["ssh"],
        event_count=1,
        status="active",
    )
    test_db.add(session)
    test_db.flush()

    # 3. Attack Event
    event = AttackEvent(
        event_id="evt-db-1",
        session_id=session.session_id,
        source_ip="192.0.2.100",
        source_service="ssh",
        asset_id="ssh-001",
        event_type="command_execution",
        username="admin",
        severity="high",
        status="executed",
        timestamp=now,
        activity={"command": "id"},
        metadata_={"host": "finance-server"},
    )
    test_db.add(event)
    test_db.flush()

    # 4. MITRE Mapping
    mitre = MitreMapping(
        event_id=event.event_id,
        technique_id="T1059.004",
        technique_name="Unix Shell",
        tactic="Execution",
        confidence=0.95,
        evidence="Simulated id execution",
    )
    test_db.add(mitre)
    test_db.commit()

    # Verify retrieval
    saved_event = test_db.query(AttackEvent).filter(AttackEvent.event_id == "evt-db-1").first()
    assert saved_event is not None
    assert saved_event.source_service == "ssh"
    assert saved_event.session is not None
    assert saved_event.session.session_id == "sess-test-1"
    assert len(saved_event.mitre_mappings) == 1
    assert saved_event.mitre_mappings[0].technique_id == "T1059.004"

