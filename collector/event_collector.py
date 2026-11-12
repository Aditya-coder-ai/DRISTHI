"""Local Event Collector and Buffer.

Receives normalized SecurityEvent objects, buffers them in memory and on disk,
and prepares batches for forwarding to Person 2's Central Backend.
"""

from __future__ import annotations

import json
from pathlib import Path
from threading import Lock
from typing import Callable, List, Optional

from shared.event_schema import SecurityEvent
from shared.logger import get_logger
from shared.config import settings

logger = get_logger("EventCollector")


class EventCollector:
    """Thread-safe event collector and in-memory buffer."""

    def __init__(self, buffer_file: Optional[Path] = None):
        self._lock = Lock()
        self._events: List[SecurityEvent] = []
        self._seen_ids: set[str] = set()
        self.buffer_file = buffer_file

    def collect(self, event: SecurityEvent) -> bool:
        """Collect and validate a single SecurityEvent.

        Returns True if newly added, False if duplicate.
        """
        with self._lock:
            if event.event_id in self._seen_ids:
                logger.debug("Duplicate event skipped: %s", event.event_id)
                return False

            self._seen_ids.add(event.event_id)
            self._events.append(event)
            logger.info(
                "Collected event: [%s] asset=%s user=%s type=%s status=%s",
                event.event_id[:8],
                event.asset_id,
                event.username or "none",
                event.event_type,
                event.status,
            )

            if self.buffer_file:
                self._persist_event(event)

            return True

    def _persist_event(self, event: SecurityEvent) -> None:
        """Append event to local buffer file."""
        if not self.buffer_file:
            return
        try:
            self.buffer_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.buffer_file, "a", encoding="utf-8") as f:
                f.write(event.model_dump_json() + "\n")
        except Exception as exc:
            logger.error("Failed to persist event to buffer file: %s", exc)

    def get_all(self) -> List[SecurityEvent]:
        """Return a copy of all buffered events."""
        with self._lock:
            return list(self._events)

    def get_by_asset(self, asset_id: str) -> List[SecurityEvent]:
        """Filter events by asset_id."""
        with self._lock:
            return [e for e in self._events if e.asset_id == asset_id]

    def get_by_type(self, event_type: str) -> List[SecurityEvent]:
        """Filter events by event_type."""
        with self._lock:
            return [e for e in self._events if e.event_type == event_type]

    def count(self) -> int:
        """Return count of collected events."""
        with self._lock:
            return len(self._events)

    def clear(self) -> None:
        """Clear all buffered events."""
        with self._lock:
            self._events.clear()
            self._seen_ids.clear()


# Global shared collector instance for local operations
global_collector = EventCollector()
