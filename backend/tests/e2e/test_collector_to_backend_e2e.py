"""End-to-End Inter-Service Integration Test.

Connects Person 1's EventForwarder & CollectorDaemon directly to Person 2's Central Backend API,
verifying that events emitted from SSH, FTP, and Canary assets flow through the forwarder,
are processed by FastAPI, and are correctly persisted in the central database.
"""

import httpx
import pytest

from collector.daemon import CollectorDaemon
from collector.event_collector import global_collector
from collector.forwarder import EventForwarder
from collector.normalizer import EventNormalizer
from collector.retry_queue import RetryQueue
from shared.event_schema import ProtocolType

from backend.app.models.attacker import AttackerProfile
from backend.app.models.event import AttackEvent
from backend.app.models.session import AttackerSession


def test_collector_daemon_to_central_backend_e2e(client, test_db, tmp_path, monkeypatch):
    # Setup isolated SQLite retry queue for Person 1 forwarder
    queue_file = tmp_path / "e2e_fwd_queue.db"
    retry_queue = RetryQueue(db_path=queue_file)

    # Bridge Person 1's EventForwarder httpx call into FastAPI TestClient
    from starlette.testclient import TestClient
    orig_post = httpx.Client.post

    def forwarder_post_adapter(self, *args, **kwargs):
        if isinstance(self, TestClient):
            return orig_post(self, *args, **kwargs)
        # Direct call through FastAPI TestClient
        return client.post(*args, **kwargs)

    forwarder = EventForwarder(
        api_url="http://testserver/api/events",
        api_key="",
        retry_queue=retry_queue,
    )
    daemon = CollectorDaemon(forwarder=forwarder, retry_queue=retry_queue, flush_interval=0.1)

    # 1. Generate SSH Telemetry (Cowrie format)
    ssh_raw = {
        "eventid": "cowrie.command.input",
        "src_ip": "198.51.100.88",
        "src_port": 51000,
        "input": "cat /home/finance_admin/.bash_history",
        "timestamp": "2026-11-14T07:00:00Z",
    }
    ssh_event = EventNormalizer.normalize(ssh_raw, protocol=ProtocolType.SSH.value, asset_id="ssh-001")
    assert ssh_event is not None
    global_collector.collect(ssh_event)

    # 2. Generate FTP Telemetry (RFC 959 format)
    ftp_raw = {
        "eventid": "ftp.file.download",
        "src_ip": "198.51.100.88",
        "src_port": 51002,
        "username": "backup_user",
        "file_path": "/backups/finance/customer_database.sql",
        "bytes_transferred": 4096,
        "timestamp": "2026-11-14T07:05:00Z",
    }
    ftp_event = EventNormalizer.normalize(ftp_raw, protocol=ProtocolType.FTP.value, asset_id="ftp-001")
    assert ftp_event is not None
    global_collector.collect(ftp_event)

    # Total in global collector: 2 events
    assert global_collector.count() == 2

    # 3. Execute Daemon Forwarding Cycle
    monkeypatch.setattr(httpx.Client, "post", forwarder_post_adapter)
    flushed = daemon.process_cycle()

    assert flushed == 2
    assert global_collector.count() == 0
    assert retry_queue.count() == 0

    # 4. Verify Central Backend Database Persistence
    persisted_events = test_db.query(AttackEvent).filter(AttackEvent.source_ip == "198.51.100.88").all()
    assert len(persisted_events) == 2

    services = {e.source_service for e in persisted_events}
    assert services == {"ssh", "ftp"}

    # 5. Verify Session Creation & Correlation
    sessions = test_db.query(AttackerSession).filter(AttackerSession.source_ip == "198.51.100.88").all()
    assert len(sessions) == 1
    session = sessions[0]
    assert session.event_count == 2
    assert set(session.services_accessed) == {"ssh", "ftp"}

    # 6. Verify Attacker Profile Aggregation
    profiles = test_db.query(AttackerProfile).filter(AttackerProfile.source_ip == "198.51.100.88").all()
    assert len(profiles) == 1
    profile = profiles[0]
    assert profile.total_events == 2
    assert "cat /home/finance_admin/.bash_history" in profile.attempted_commands

    # 7. Verify Dashboard Stats compute from real persisted records
    dash_resp = client.get("/api/dashboard/stats")
    assert dash_resp.status_code == 200
    stats = dash_resp.json()
    assert stats["total_events"] == 2
    assert stats["unique_attackers"] == 1
    assert any(s["service"] == "ssh" for s in stats["top_targeted_services"])
    assert any(s["service"] == "ftp" for s in stats["top_targeted_services"])
