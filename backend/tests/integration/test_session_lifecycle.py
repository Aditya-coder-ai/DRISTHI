"""Integration tests for Attacker Session lifecycle and state transitions."""

from backend.app.models.session import AttackerSession
from backend.app.services.ingestion_service import IngestionService


def test_session_grouping_and_lifecycle(test_db):
    service = IngestionService(test_db)

    # 1. First event: SSH login
    evt1 = {
        "event_id": "sess-evt-1",
        "asset_id": "ssh-001",
        "event_type": "login_success",
        "source_ip": "203.0.113.10",
        "username": "finance_admin",
        "protocol": "SSH",
        "timestamp": "2026-11-14T06:00:00Z",
        "status": "success",
    }
    service.ingest_payload(evt1)
    sessions = test_db.query(AttackerSession).filter(AttackerSession.source_ip == "203.0.113.10").all()
    assert len(sessions) == 1
    session = sessions[0]
    assert session.event_count == 1
    assert session.status == "active"
    assert "ssh" in session.services_accessed

    # 2. Second event: FTP access from same IP shortly after (same session)
    evt2 = {
        "event_id": "sess-evt-2",
        "asset_id": "ftp-001",
        "event_type": "file_access",
        "source_ip": "203.0.113.10",
        "username": "backup_user",
        "protocol": "FTP",
        "timestamp": "2026-11-14T06:05:00Z",
        "status": "executed",
    }
    service.ingest_payload(evt2)
    test_db.refresh(session)
    assert session.event_count == 2
    assert "ftp" in session.services_accessed

    # 3. Third event: Canary trigger (should escalate session)
    evt3 = {
        "event_id": "sess-evt-3",
        "asset_id": "db-001",
        "event_type": "canary_triggered",
        "source_ip": "203.0.113.10",
        "protocol": "DATABASE",
        "timestamp": "2026-11-14T06:10:00Z",
        "status": "detected",
    }
    service.ingest_payload(evt3)
    test_db.refresh(session)
    assert session.status == "escalated"

    # 4. Fourth event: Session disconnect
    evt4 = {
        "event_id": "sess-evt-4",
        "asset_id": "ssh-001",
        "event_type": "session_disconnect",
        "source_ip": "203.0.113.10",
        "protocol": "SSH",
        "timestamp": "2026-11-14T06:15:00Z",
        "status": "closed",
    }
    service.ingest_payload(evt4)
    test_db.refresh(session)
    assert session.status == "closed"

