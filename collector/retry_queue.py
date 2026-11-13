"""Persistent SQLite Retry Queue for Central Backend Event Forwarding.

Ensures at-least-once delivery with exponential backoff and event deduplication.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from threading import Lock
from typing import List, Optional, Tuple

from shared.config import settings
from shared.event_schema import SecurityEvent
from shared.logger import get_logger

logger = get_logger("RetryQueue")

DEFAULT_DB_PATH = settings.BASE_DIR / "var" / "data" / "retry_queue.db"


class RetryQueue:
    """Thread-safe persistent queue for buffering undelivered security events."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock:
            with self._get_connection() as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS retry_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_id TEXT UNIQUE NOT NULL,
                        event_data TEXT NOT NULL,
                        retry_count INTEGER NOT NULL DEFAULT 0,
                        next_retry_at REAL NOT NULL,
                        created_at REAL NOT NULL,
                        status TEXT NOT NULL DEFAULT 'PENDING'
                    )
                    """
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_retry_ready ON retry_events (status, next_retry_at)"
                )
                conn.commit()

    def enqueue(self, event: SecurityEvent) -> bool:
        """Enqueue an event for delayed retry.
        
        Returns True if inserted, False if event_id already exists.
        """
        now = time.time()
        event_json = event.model_dump_json()
        with self._lock:
            try:
                with self._get_connection() as conn:
                    conn.execute(
                        """
                        INSERT INTO retry_events (event_id, event_data, retry_count, next_retry_at, created_at, status)
                        VALUES (?, ?, 0, ?, ?, 'PENDING')
                        """,
                        (event.event_id, event_json, now, now),
                    )
                    conn.commit()
                logger.info("Enqueued event %s for retry", event.event_id[:8])
                return True
            except sqlite3.IntegrityError:
                logger.debug("Event %s already in retry queue, skipping duplicate", event.event_id[:8])
                return False
            except Exception as exc:
                logger.error("Failed to enqueue event %s: %s", event.event_id, exc)
                return False

    def dequeue_batch(self, batch_size: int = 50) -> List[Tuple[int, SecurityEvent, int]]:
        """Fetch up to batch_size events ready for retry.
        
        Returns list of (row_id, SecurityEvent, retry_count).
        """
        now = time.time()
        items: List[Tuple[int, SecurityEvent, int]] = []
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.execute(
                        """
                        SELECT id, event_data, retry_count
                        FROM retry_events
                        WHERE status = 'PENDING' AND next_retry_at <= ?
                        ORDER BY id ASC
                        LIMIT ?
                        """,
                        (now, batch_size),
                    )
                    rows = cursor.fetchall()
                    for r in rows:
                        try:
                            data = json.loads(r["event_data"])
                            evt = SecurityEvent(**data)
                            items.append((r["id"], evt, r["retry_count"]))
                        except Exception as parse_err:
                            logger.error("Corrupted event in queue row %d: %s", r["id"], parse_err)
            except Exception as exc:
                logger.error("Failed to fetch retry batch: %s", exc)
        return items

    def mark_success(self, row_ids: List[int]) -> None:
        """Delete successfully delivered events from queue."""
        if not row_ids:
            return
        with self._lock:
            try:
                with self._get_connection() as conn:
                    placeholders = ",".join("?" for _ in row_ids)
                    conn.execute(
                        f"DELETE FROM retry_events WHERE id IN ({placeholders})",
                        row_ids,
                    )
                    conn.commit()
                logger.info("Successfully delivered and purged %d events from retry queue", len(row_ids))
            except Exception as exc:
                logger.error("Failed to mark events as successful: %s", exc)

    def mark_failure(self, row_ids: List[int], base_backoff: float = 2.0, max_retries: int = 5) -> None:
        """Increment retry count and compute exponential backoff for failed events.
        
        If retry_count reaches max_retries, mark as DEAD_LETTER.
        """
        if not row_ids:
            return
        now = time.time()
        with self._lock:
            try:
                with self._get_connection() as conn:
                    for row_id in row_ids:
                        cursor = conn.execute(
                            "SELECT retry_count FROM retry_events WHERE id = ?",
                            (row_id,),
                        )
                        row = cursor.fetchone()
                        if not row:
                            continue
                        current_count = row["retry_count"] + 1
                        if current_count >= max_retries:
                            conn.execute(
                                "UPDATE retry_events SET status = 'DEAD_LETTER', retry_count = ? WHERE id = ?",
                                (current_count, row_id),
                            )
                            logger.warning("Event row %d exceeded max retries (%d), marked DEAD_LETTER", row_id, max_retries)
                        else:
                            delay = base_backoff * (2 ** (current_count - 1))
                            next_retry = now + delay
                            conn.execute(
                                "UPDATE retry_events SET retry_count = ?, next_retry_at = ? WHERE id = ?",
                                (current_count, next_retry, row_id),
                            )
                    conn.commit()
            except Exception as exc:
                logger.error("Failed to mark retry failure: %s", exc)

    def count(self, status: str = "PENDING") -> int:
        """Return count of items in queue with specified status."""
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.execute(
                        "SELECT COUNT(*) FROM retry_events WHERE status = ?",
                        (status,),
                    )
                    return cursor.fetchone()[0]
            except Exception:
                return 0

    def clear(self) -> None:
        """Purge all entries from the retry database."""
        with self._lock:
            try:
                with self._get_connection() as conn:
                    conn.execute("DELETE FROM retry_events")
                    conn.commit()
            except Exception as exc:
                logger.error("Failed to clear retry queue: %s", exc)
