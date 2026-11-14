"""End-to-End Multi-Service Integration Test for Person 1 Deception Platform.

Verifies complete cross-service lifecycle:
1. SSH intrusion event normalization (ssh-001)
2. FTP exfiltration event normalization (ftp-001)
3. Web Admin portal event normalization (web-001)
4. Database PostgreSQL & MySQL event normalization (db-001)
5. Canary credential triggering & cross-service lateral movement detection
6. Central Collector forwarding daemon batching, buffering, and delivery to Central Backend.
"""

import httpx
import pytest

from collector.daemon import CollectorDaemon
from collector.event_collector import global_collector
from collector.forwarder import EventForwarder
from collector.normalizer import EventNormalizer
from collector.retry_queue import RetryQueue
from services.credentials.registry import CredentialRegistry
from shared.event_schema import EventType, ProtocolType, SecurityEvent


@pytest.fixture
def e2e_system(tmp_path):
    """Setup isolated integrated platform environment."""
    queue_db = tmp_path / "e2e_retry_queue.db"
    creds_file = tmp_path / "e2e_creds.json"
    queue = RetryQueue(db_path=queue_db)
    registry = CredentialRegistry(storage_file=creds_file)

    delivered_batches = []

    def mock_backend_post(client, url, json=None, headers=None):
        delivered_batches.append(json)
        return httpx.Response(200, json={"status": "accepted", "count": len(json)})

    forwarder = EventForwarder(
        api_url="http://central-backend.corp/api/events",
        api_key="drishti-sec-token-2026",
        retry_queue=queue,
    )
    daemon = CollectorDaemon(forwarder=forwarder, retry_queue=queue, flush_interval=0.1)

    global_collector.clear()
    return daemon, queue, registry, delivered_batches, mock_backend_post


def test_full_cross_service_lifecycle_e2e(e2e_system, monkeypatch):
    """Execute end-to-end telemetry generation, normalization, canary correlation, and forwarding."""
    daemon, queue, registry, delivered_batches, mock_backend_post = e2e_system
    monkeypatch.setattr(httpx.Client, "post", mock_backend_post)

    # 1. SSH Intrusion Event (Cowrie raw format)
    ssh_raw = {
        "eventid": "cowrie.command.input",
        "src_ip": "198.51.100.10",
        "src_port": 50220,
        "input": "cat /home/finance_admin/.bash_history",
        "timestamp": "2026-11-14T01:00:00Z",
    }
    ssh_event = EventNormalizer.normalize(ssh_raw, protocol=ProtocolType.SSH.value, asset_id="ssh-001")
    assert ssh_event is not None
    assert ssh_event.asset_id == "ssh-001"
    global_collector.collect(ssh_event)

    # 2. FTP Lateral Movement & Exfiltration Event (FTP raw format)
    ftp_raw = {
        "eventid": "ftp.file.download",
        "src_ip": "198.51.100.10",
        "src_port": 50222,
        "username": "backup_user",
        "file_path": "/backups/finance/db_migration_notes.txt",
        "bytes_transferred": 2048,
        "timestamp": "2026-11-14T01:05:00Z",
    }
    ftp_event = EventNormalizer.normalize(ftp_raw, protocol=ProtocolType.FTP.value, asset_id="ftp-001")
    assert ftp_event is not None
    assert ftp_event.asset_id == "ftp-001"
    global_collector.collect(ftp_event)

    # 3. Web Admin Portal Reconnaissance Event (HTTP raw format)
    web_raw = {
        "eventid": "web.bait.trigger",
        "src_ip": "198.51.100.10",
        "src_port": 50224,
        "username": "admin",
        "bait_file": "database_config.json",
        "bait_credential_targeted": "database_root",
        "timestamp": "2026-11-14T01:10:00Z",
    }
    web_event = EventNormalizer.normalize(web_raw, protocol=ProtocolType.HTTP.value, asset_id="web-001")
    assert web_event is not None
    assert web_event.asset_id == "web-001"
    global_collector.collect(web_event)

    # 4. Database PostgreSQL Query Event (Database raw format)
    db_raw = {
        "eventid": "db.query.execution",
        "src_ip": "198.51.100.10",
        "src_port": 50226,
        "username": "database_root",
        "database": "corporate_finance",
        "query": "SELECT * FROM executive_compensation;",
        "sub_protocol": "PostgreSQL",
        "timestamp": "2026-11-14T01:15:00Z",
    }
    db_event = EventNormalizer.normalize(db_raw, protocol=ProtocolType.DATABASE.value, asset_id="db-001")
    assert db_event is not None
    assert db_event.asset_id == "db-001"
    global_collector.collect(db_event)

    # 5. Canary Evaluation & Cross-Service Lateral Movement Detection
    # Using 'backup_user' (seeded on ftp-001) on 'db-001'
    is_bait, canary_evt, reuse_evt = registry.evaluate_interaction(
        username="backup_user",
        password_attempt="Backup@2026",
        target_asset="db-001",
        src_ip="198.51.100.10",
        protocol="DATABASE",
    )
    assert is_bait is True
    assert canary_evt is not None
    assert reuse_evt is not None

    # Global collector now holds: SSH + FTP + Web + DB + CANARY + REUSE = 6 events
    assert global_collector.count() == 6

    # 6. Central Collector Forwarding Daemon processing cycle
    flushed_count = daemon.process_cycle()
    assert flushed_count == 6
    assert global_collector.count() == 0
    assert queue.count() == 0
    assert len(delivered_batches) == 1

    batch = delivered_batches[0]
    assert len(batch) == 6

    # Verify all asset IDs and event types are present in delivered payload
    assets_in_batch = {e["asset_id"] for e in batch}
    assert assets_in_batch == {"ssh-001", "ftp-001", "web-001", "db-001"}

    event_types_in_batch = {e["event_type"] for e in batch}
    assert EventType.COMMAND_EXECUTION.value in event_types_in_batch
    assert EventType.FILE_DOWNLOAD.value in event_types_in_batch
    assert EventType.BAIT_CREDENTIAL_TRIGGER.value in event_types_in_batch
    assert EventType.QUERY_EXECUTION.value in event_types_in_batch
    assert EventType.CANARY_TRIGGERED.value in event_types_in_batch
    assert EventType.CREDENTIAL_REUSE.value in event_types_in_batch

    # Verify daemon health status is HEALTHY
    stats = daemon.get_stats()
    assert stats["status"] == "HEALTHY"
    assert stats["total_delivered"] == 6

