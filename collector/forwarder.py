"""Central Backend Event Forwarder.

Transmits normalized SecurityEvent objects to Person 2's Central Backend API.
Handles batching, network resilience, authentication, and offline buffering via RetryQueue.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

import httpx

from collector.retry_queue import RetryQueue
from shared.config import settings
from shared.event_schema import SecurityEvent
from shared.logger import get_logger

logger = get_logger("EventForwarder")


class EventForwarder:
    """Dispatches SecurityEvent records to the central backend API with retry fallback."""

    def __init__(
        self,
        api_url: Optional[str] = None,
        api_key: Optional[str] = None,
        batch_size: Optional[int] = None,
        retry_limit: Optional[int] = None,
        timeout: float = 5.0,
        retry_queue: Optional[RetryQueue] = None,
    ):
        self.api_url = api_url or settings.BACKEND_API_URL
        self.api_key = api_key or settings.BACKEND_API_KEY
        self.batch_size = batch_size or settings.EVENT_BATCH_SIZE
        self.retry_limit = retry_limit or settings.RETRY_LIMIT
        self.timeout = timeout
        self.retry_queue = retry_queue or RetryQueue()

    def _get_headers(self) -> Dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Drishti-Deception-Collector/1.0",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
            headers["X-API-Key"] = self.api_key
        return headers

    def send_event(self, event: SecurityEvent) -> bool:
        """Send a single SecurityEvent to the backend. Enqueues in retry queue if failed."""
        payload = [event.model_dump(mode="json")]
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(self.api_url, json=payload, headers=self._get_headers())
                if resp.status_code in (200, 201, 202):
                    logger.info("Successfully forwarded event %s to backend", event.event_id[:8])
                    return True
                else:
                    logger.warning(
                        "Backend rejected event %s (HTTP %d: %s). Buffering for retry.",
                        event.event_id[:8],
                        resp.status_code,
                        resp.text[:100],
                    )
        except Exception as exc:
            logger.warning("Network failure forwarding event %s: %s. Buffering for retry.", event.event_id[:8], exc)

        # On delivery failure, buffer in retry queue
        self.retry_queue.enqueue(event)
        return False

    def send_batch(self, events: List[SecurityEvent]) -> bool:
        """Send a list of events as a batch. Enqueues failed events in retry queue."""
        if not events:
            return True

        payload = [e.model_dump(mode="json") for e in events]
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(self.api_url, json=payload, headers=self._get_headers())
                if resp.status_code in (200, 201, 202):
                    logger.info("Successfully forwarded batch of %d events to backend", len(events))
                    return True
                else:
                    logger.warning(
                        "Backend rejected batch of %d events (HTTP %d). Buffering in retry queue.",
                        len(events),
                        resp.status_code,
                    )
        except Exception as exc:
            logger.warning("Network failure forwarding batch of %d events: %s", len(events), exc)

        # Buffer all failed events into retry queue
        for event in events:
            self.retry_queue.enqueue(event)
        return False

    def flush_retry_queue(self) -> int:
        """Attempt to deliver pending events from the retry queue.
        
        Returns count of successfully delivered events.
        """
        pending_batch = self.retry_queue.dequeue_batch(batch_size=self.batch_size)
        if not pending_batch:
            return 0

        row_ids = [item[0] for item in pending_batch]
        events = [item[1] for item in pending_batch]
        payload = [e.model_dump(mode="json") for e in events]

        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(self.api_url, json=payload, headers=self._get_headers())
                if resp.status_code in (200, 201, 202):
                    self.retry_queue.mark_success(row_ids)
                    logger.info("Successfully flushed %d queued events to backend", len(events))
                    return len(events)
                else:
                    logger.warning("Flush attempt rejected (HTTP %d)", resp.status_code)
                    self.retry_queue.mark_failure(row_ids, max_retries=self.retry_limit)
                    return 0
        except Exception as exc:
            logger.warning("Flush network error: %s", exc)
            self.retry_queue.mark_failure(row_ids, max_retries=self.retry_limit)
            return 0
