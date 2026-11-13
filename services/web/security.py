"""Session tracking, rate limiting, and telemetry dispatch for Web Admin Portal."""

from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from threading import Lock

from shared.config import settings
from shared.logger import get_logger
from services.web.web_event_adapter import WebEventAdapter
from collector.event_collector import global_collector

logger = get_logger("WebSecurity")

# In-memory session store
_SESSION_LOCK = Lock()
ACTIVE_SESSIONS: Dict[str, Dict[str, Any]] = {}

# In-memory login attempt tracker: key -> list of float timestamps
_ATTEMPT_LOCK = Lock()
LOGIN_ATTEMPTS: Dict[str, List[float]] = {}
ATTEMPT_WINDOW_SECONDS = 900  # 15 minutes


def record_login_attempt(src_ip: str, username: str) -> int:
    """Record an authentication attempt and return the count of recent attempts."""
    now = time.time()
    key = f"{src_ip}:{username.strip().lower()}"
    with _ATTEMPT_LOCK:
        times = LOGIN_ATTEMPTS.get(key, [])
        # Prune older than window
        valid_times = [t for t in times if now - t <= ATTEMPT_WINDOW_SECONDS]
        valid_times.append(now)
        LOGIN_ATTEMPTS[key] = valid_times
        return len(valid_times)


def reset_login_attempts(src_ip: str, username: str) -> None:
    """Reset attempt counter upon successful login."""
    key = f"{src_ip}:{username.strip().lower()}"
    with _ATTEMPT_LOCK:
        LOGIN_ATTEMPTS.pop(key, None)


def create_session(username: str, role: str = "Administrator") -> str:
    """Create a new session token."""
    session_id = f"apex_sess_{uuid.uuid4().hex}"
    with _SESSION_LOCK:
        ACTIVE_SESSIONS[session_id] = {
            "username": username,
            "role": role,
            "created_at": time.time(),
        }
    return session_id


def get_session(session_id: Optional[str]) -> Optional[Dict[str, Any]]:
    """Retrieve session info if valid."""
    if not session_id:
        return None
    with _SESSION_LOCK:
        return ACTIVE_SESSIONS.get(session_id)


def delete_session(session_id: Optional[str]) -> None:
    """Destroy session token."""
    if not session_id:
        return
    with _SESSION_LOCK:
        ACTIVE_SESSIONS.pop(session_id, None)


def log_web_telemetry(raw_payload: Dict[str, Any]) -> None:
    """Write raw telemetry to web.json log and forward normalized event to collector."""
    # Ensure log directory exists
    try:
        settings.WEB_LOG_DIR.mkdir(parents=True, exist_ok=True)
        with open(settings.WEB_JSON_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(raw_payload) + "\n")
    except Exception as exc:
        logger.error("Failed to write web log to %s: %s", settings.WEB_JSON_LOG, exc)

    # Normalize and collect
    try:
        sec_event = WebEventAdapter.normalize(raw_payload, asset_id=settings.WEB_ASSET_ID)
        if sec_event:
            global_collector.collect(sec_event)
    except Exception as exc:
        logger.error("Failed to normalize/collect web event: %s", exc)
