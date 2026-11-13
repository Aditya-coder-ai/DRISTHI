"""Tests for EventForwarder and SQLite RetryQueue."""

import time
from pathlib import Path
import httpx
import pytest

from collector.forwarder import EventForwarder
from collector.retry_queue import RetryQueue
from shared.event_schema import EventStatus, EventType, ProtocolType, SecurityEvent


@pytest.fixture
def temp_queue(tmp_path):
    """Create isolated SQLite retry queue for testing."""
    db_file = tmp_path / "test_retry_queue.db"
    queue = RetryQueue(db_path=db_file)
    return queue


def make_sample_event(event_id: str = "evt-test-001", user: str = "finance_admin") -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id,
        asset_id="web-001",
        event_type=EventType.LOGIN_SUCCESS.value,
        source_ip="192.168.1.100",
        source_port=54321,
        username=user,
        protocol=ProtocolType.HTTP.value,
        timestamp="2026-11-13T12:00:00Z",
        status=EventStatus.SUCCESS.value,
        metadata={"portal": "Apex Internal Management System"},
    )


def test_retry_queue_enqueue_and_deduplication(temp_queue):
    """Test enqueuing events and verifying deduplication by event_id."""
    evt = make_sample_event("evt-dedup-1")
    assert temp_queue.enqueue(evt) is True
    # Duplicate insertion should return False and not increment count
    assert temp_queue.enqueue(evt) is False
    assert temp_queue.count() == 1


def test_retry_queue_dequeue_batch_and_mark_success(temp_queue):
    """Test batch retrieval and purging upon successful delivery."""
    for i in range(5):
        temp_queue.enqueue(make_sample_event(f"evt-batch-{i}"))

    assert temp_queue.count() == 5
    batch = temp_queue.dequeue_batch(batch_size=3)
    assert len(batch) == 3

    # Mark first 2 as successful
    row_ids = [batch[0][0], batch[1][0]]
    temp_queue.mark_success(row_ids)
    assert temp_queue.count() == 3


def test_retry_queue_exponential_backoff_and_dead_letter(temp_queue):
    """Test failure retry count increments and dead letter transition."""
    evt = make_sample_event("evt-fail-1")
    temp_queue.enqueue(evt)

    batch = temp_queue.dequeue_batch(batch_size=1)
    row_id = batch[0][0]

    # Simulate 4 failures
    for _ in range(4):
        temp_queue.mark_failure([row_id], base_backoff=0.01, max_retries=5)

    assert temp_queue.count(status="PENDING") == 1

    # 5th failure exceeds max_retries (5) -> marked as DEAD_LETTER
    temp_queue.mark_failure([row_id], base_backoff=0.01, max_retries=5)
    assert temp_queue.count(status="PENDING") == 0
    assert temp_queue.count(status="DEAD_LETTER") == 1


def test_forwarder_send_event_success(temp_queue, monkeypatch):
    """Test successful event transmission to central backend."""
    forwarder = EventForwarder(
        api_url="http://mock-backend.corp/api/events",
        api_key="test-key-123",
        retry_queue=temp_queue,
    )

    def mock_post(client, url, json=None, headers=None):
        return httpx.Response(200, json={"status": "received", "count": len(json)})

    monkeypatch.setattr(httpx.Client, "post", mock_post)

    evt = make_sample_event("evt-fwd-01")
    success = forwarder.send_event(evt)
    assert success is True
    # Since delivery succeeded, nothing should be buffered
    assert temp_queue.count() == 0


def test_forwarder_send_event_failure_buffers_to_retry_queue(temp_queue, monkeypatch):
    """Test that connection error or 500 error buffers event in retry queue."""
    forwarder = EventForwarder(
        api_url="http://mock-backend.corp/api/events",
        retry_queue=temp_queue,
    )

    def mock_post_fail(client, url, json=None, headers=None):
        raise httpx.ConnectError("Connection refused by backend")

    monkeypatch.setattr(httpx.Client, "post", mock_post_fail)

    evt = make_sample_event("evt-fail-buffer-01")
    success = forwarder.send_event(evt)
    assert success is False
    # Event should be safely buffered in retry queue
    assert temp_queue.count() == 1


def test_forwarder_flush_retry_queue(temp_queue, monkeypatch):
    """Test flushing retry queue when backend recovers."""
    # Pre-populate queue with 2 events
    temp_queue.enqueue(make_sample_event("evt-recovery-01"))
    temp_queue.enqueue(make_sample_event("evt-recovery-02"))
    assert temp_queue.count() == 2

    forwarder = EventForwarder(
        api_url="http://mock-backend.corp/api/events",
        retry_queue=temp_queue,
    )

    def mock_post_recover(client, url, json=None, headers=None):
        return httpx.Response(200, json={"status": "accepted"})

    monkeypatch.setattr(httpx.Client, "post", mock_post_recover)

    flushed_count = forwarder.flush_retry_queue()
    assert flushed_count == 2
    assert temp_queue.count() == 0

