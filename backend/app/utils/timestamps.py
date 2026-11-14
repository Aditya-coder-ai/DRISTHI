"""Timestamp normalization and comparison utilities."""

from datetime import datetime, timezone
from typing import Any, Optional


def ensure_utc(dt: Any) -> datetime:
    """Guarantees a datetime object is timezone-aware and set to UTC."""
    if dt is None:
        return datetime.now(timezone.utc)
    if isinstance(dt, str):
        cleaned = dt.replace("Z", "+00:00")
        dt = datetime.fromisoformat(cleaned)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

