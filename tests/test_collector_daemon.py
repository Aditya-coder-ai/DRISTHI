"""Tests for Central Event Collection & Forwarding Daemon."""

import json
from pathlib import Path
import httpx
import pytest

from collector.daemon import CollectorDaemon
from collector.event_collector import global_collector
from collector.forwarder import EventForwarder
from collector.retry_queue import RetryQueue
from shared.event_schema import EventStatus, EventType, ProtocolType, SecurityEvent


@pytest.fixture
def temp_daemon_env(tmp_path):
    """Setup isolated retry queue and collector daemon for testing."""
    queue_db = tmp_path / "daemon_test_queue.db"
    queue = RetryQueue(db_path=queue_db)
    forwarder = EventForwarder(
        api_url="http://mock-backend.corp/api/events",
        retry_queue=queue,
    )
    daemon = CollectorDaemon(forwarder=forwarder, retry_queue=queue, flush_interval=0.1)
    return daemon, queue, forwarder


def make_test_event(event_id: str, asset: str = "db-001") -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id,
        asset_id=asset,
        event_type=EventType.QUERY_EXECUTION.value,
        source_ip="10.0.0.99",
        protocol=ProtocolType.DATABASE.value,
        status=EventStatus.EXECUTED.value,
        metadata={"query": "SELECT * FROM general_ledger;"},
    )


def test_daemon_health_stats_initial(temp_daemon_env):
    """Verify initial health check metrics structure."""
    daemon, queue, forwarder = temp_daemon_env
    stats = daemon.get_stats()
    assert stats["status"] == "HEALTHY"
    assert stats["pending_event_count"] == 0
    assert stats["dead_letter_count"] == 0
    assert stats["failed_delivery_count"] == 0


def test_daemon_drain_collector_and_flush_success(temp_daemon_env, monkeypatch):
    """Test daemon cycle drains in-memory global collector into queue and flushes."""
    daemon, queue, forwarder = temp_daemon_env

    # Emit 3 events into global collector
    global_collector.clear()
    for i in range(3):
        global_collector.collect(make_test_event(f"evt-daemon-{i}"))
    assert global_collector.count() == 3

    # Mock backend HTTP 200
    def mock_post(client, url, json=None, headers=None):
        return httpx.Response(200, json={"status": "accepted"})

    monkeypatch.setattr(httpx.Client, "post", mock_post)

    # Run single process cycle
    flushed = daemon.process_cycle()
    assert flushed == 3
    # In-memory collector should now be drained
    assert global_collector.count() == 0
    # Queue should be empty after successful flush
    assert queue.count() == 0

    stats = daemon.get_stats()
    assert stats["total_delivered"] == 3
    assert stats["last_successful_delivery"] is not None


def test_daemon_flush_failure_and_degraded_status(temp_daemon_env, monkeypatch):
    """Test daemon handles backend network failure and tracks metrics."""
    daemon, queue, forwarder = temp_daemon_env

    # Enqueue events
    queue.enqueue(make_test_event("evt-fail-1"))
    queue.enqueue(make_test_event("evt-fail-2"))

    def mock_post_fail(client, url, json=None, headers=None):
        raise httpx.ConnectError("Connection refused by backend")

    monkeypatch.setattr(httpx.Client, "post", mock_post_fail)

    # Run cycle
    flushed = daemon.process_cycle()
    assert flushed == 0
    assert queue.count() == 2
    assert daemon.failed_deliveries >= 1

