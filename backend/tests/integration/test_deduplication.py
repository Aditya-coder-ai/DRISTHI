"""Integration tests for event deduplication and transaction safety."""

from backend.app.models.event import AttackEvent
from backend.app.services.ingestion_service import IngestionService


def test_event_deduplication_by_event_id(test_db):
    service = IngestionService(test_db)
    payload = {
        "event_id": "evt-dedup-100",
        "asset_id": "ssh-001",
        "event_type": "command_execution",
        "source_ip": "198.51.100.50",
        "protocol": "SSH",
        "timestamp": "2026-11-14T05:00:00Z",
        "status": "executed",
        "metadata": {"command": "whoami"},
    }

    # 1. First submission: should succeed and persist
    res1 = service.ingest_payload(payload)
    assert res1.status == "success"
    assert res1.persisted == 1
    assert res1.duplicates_skipped == 0
    assert test_db.query(AttackEvent).filter(AttackEvent.event_id == "evt-dedup-100").count() == 1

    # 2. Duplicate submission: should be safely detected and skipped without error
    res2 = service.ingest_payload(payload)
    assert res2.status == "success"
    assert res2.persisted == 0
    assert res2.duplicates_skipped == 1
    assert test_db.query(AttackEvent).filter(AttackEvent.event_id == "evt-dedup-100").count() == 1

