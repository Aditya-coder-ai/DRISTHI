"""Centralized Dynamic Bait Credentials Registry and Canary Tracking.

Maintains believable bait credentials across all honeypots (SSH, FTP, Web, Database).
Detects credential exposure, tracks usage history, correlates cross-service credential reuse,
and generates high-priority CANARY_TRIGGERED and CREDENTIAL_REUSE security events.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import string
import time
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List, Optional, Tuple

from shared.config import settings
from shared.event_schema import EventStatus, EventType, SecurityEvent
from shared.logger import get_logger
from collector.event_collector import global_collector

logger = get_logger("CredentialRegistry")


class CredentialStatus:
    ACTIVE = "ACTIVE"
    TRIGGERED = "TRIGGERED"
    ROTATED = "ROTATED"
    EXPOSED = "EXPOSED"


class BaitCredential:
    """Represents an individual trackable decoy bait credential."""

    def __init__(
        self,
        credential_id: str,
        username: str,
        password: str,
        origin_asset: str,
        planted_locations: Optional[List[str]] = None,
        description: str = "",
        status: str = CredentialStatus.ACTIVE,
        created_at: Optional[str] = None,
        last_triggered_at: Optional[str] = None,
        trigger_count: int = 0,
        usage_history: Optional[List[Dict[str, Any]]] = None,
    ):
        self.credential_id = credential_id
        self.username = username
        self.password_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
        self._raw_password = password  # Accessible only for honeypot seed generation
        self.origin_asset = origin_asset
        self.planted_locations = planted_locations or []
        self.description = description
        self.status = status
        self.created_at = created_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.last_triggered_at = last_triggered_at
        self.trigger_count = trigger_count
        self.usage_history = usage_history or []

    def verify_password(self, password_attempt: str) -> bool:
        """Verify password without exposing plaintext in logs."""
        attempt_hash = hashlib.sha256(password_attempt.encode("utf-8")).hexdigest()
        return secrets.compare_digest(self.password_hash, attempt_hash)

    def to_dict(self, include_raw: bool = False) -> Dict[str, Any]:
        data = {
            "credential_id": self.credential_id,
            "username": self.username,
            "origin_asset": self.origin_asset,
            "planted_locations": self.planted_locations,
            "description": self.description,
            "status": self.status,
            "created_at": self.created_at,
            "last_triggered_at": self.last_triggered_at,
            "trigger_count": self.trigger_count,
            "usage_history": self.usage_history,
        }
        if include_raw:
            data["password"] = self._raw_password
        return data


class CredentialRegistry:
    """Thread-safe centralized registry for deception bait credentials."""

    def __init__(self, storage_file: Optional[Path] = None):
        self.storage_file = storage_file or settings.CREDENTIALS_FILE
        self._lock = Lock()
        self._credentials: Dict[str, BaitCredential] = {}
        self._load_initial_credentials()

    def _load_initial_credentials(self) -> None:
        """Load credentials from file or seed defaults."""
        with self._lock:
            if self.storage_file.exists():
                try:
                    with open(self.storage_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        raw_creds = data.get("credentials", [])
                        for item in raw_creds:
                            cid = f"cred-{item['username']}"
                            cred = BaitCredential(
                                credential_id=cid,
                                username=item["username"],
                                password=item.get("password", ""),
                                origin_asset=item.get("asset", "unknown"),
                                description=item.get("description", ""),
                                planted_locations=[item.get("type", "generic")],
                            )
                            self._credentials[cred.username] = cred
                    logger.info("Loaded %d credentials from %s", len(self._credentials), self.storage_file)
                    return
                except Exception as exc:
                    logger.error("Failed to load credentials file: %s. Using default seeds.", exc)

            # Default seed credentials if file missing
            self._seed_defaults()

    def _seed_defaults(self) -> None:
        """Seed standard platform bait credentials."""
        seeds = [
            ("finance_admin", "Finance@2026", "ssh-001", ["ssh:/home/finance_admin/.bash_history", "web:/configuration"]),
            ("backup_user", "Backup@2026", "ftp-001", ["ftp:/backups/finance", "web:/configuration"]),
            ("database_root", "DBroot@2026", "db-001", ["ftp:/backups/finance/db_migration_notes.txt", "web:/configuration"]),
        ]
        for user, pwd, asset, locs in seeds:
            cid = f"cred-{user}"
            self._credentials[user] = BaitCredential(
                credential_id=cid,
                username=user,
                password=pwd,
                origin_asset=asset,
                planted_locations=locs,
                description=f"Standard bait credential for {asset}",
            )

    def register(
        self,
        username: str,
        password: str,
        origin_asset: str,
        planted_locations: Optional[List[str]] = None,
        description: str = "",
    ) -> BaitCredential:
        """Register a new bait credential."""
        with self._lock:
            cid = f"cred-{username}-{secrets.token_hex(4)}"
            cred = BaitCredential(
                credential_id=cid,
                username=username,
                password=password,
                origin_asset=origin_asset,
                planted_locations=planted_locations,
                description=description,
            )
            self._credentials[username] = cred
            logger.info("Registered new bait credential [%s] for %s", username, origin_asset)
            return cred

    def rotate(self, username: str, new_password: Optional[str] = None) -> Optional[BaitCredential]:
        """Rotate a bait credential while preserving history."""
        with self._lock:
            existing = self._credentials.get(username)
            if not existing:
                return None

            existing.status = CredentialStatus.ROTATED
            chars = string.ascii_letters + string.digits + "@#$!"
            pwd = new_password or ("".join(secrets.choice(chars) for _ in range(12)) + "@2026")

            new_cid = f"cred-{username}-rot-{int(time.time())}"
            rotated_cred = BaitCredential(
                credential_id=new_cid,
                username=username,
                password=pwd,
                origin_asset=existing.origin_asset,
                planted_locations=existing.planted_locations,
                description=f"Rotated credential from {existing.credential_id}",
            )
            self._credentials[username] = rotated_cred
            logger.info("Rotated credential for user %s", username)
            return rotated_cred

    def evaluate_interaction(
        self,
        username: str,
        password_attempt: Optional[str],
        target_asset: str,
        src_ip: str,
        protocol: str,
        src_port: Optional[int] = None,
    ) -> Tuple[bool, Optional[SecurityEvent], Optional[SecurityEvent]]:
        """Evaluate an interaction against registered bait credentials.
        
        Returns:
            (is_bait_user, canary_event, reuse_event)
        """
        with self._lock:
            cred = self._credentials.get(username)
            if not cred:
                return False, None, None

            # Verify password if provided
            matched = True
            if password_attempt is not None:
                matched = cred.verify_password(password_attempt)

            if not matched:
                return True, None, None

            # Mark credential triggered
            now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            cred.status = CredentialStatus.TRIGGERED
            cred.last_triggered_at = now_iso
            cred.trigger_count += 1
            usage_record = {
                "timestamp": now_iso,
                "target_asset": target_asset,
                "source_ip": src_ip,
                "source_port": src_port,
                "protocol": protocol,
            }
            cred.usage_history.append(usage_record)

            # 1. CANARY_TRIGGERED Event
            canary_event = SecurityEvent(
                asset_id=target_asset,
                event_type=EventType.CANARY_TRIGGERED.value,
                source_ip=src_ip,
                source_port=src_port,
                username=username,
                protocol=protocol,
                timestamp=now_iso,
                status=EventStatus.DETECTED.value,
                metadata={
                    "alert_priority": "CRITICAL",
                    "credential_id": cred.credential_id,
                    "origin_asset": cred.origin_asset,
                    "target_asset": target_asset,
                    "trigger_count": cred.trigger_count,
                    "planted_locations": cred.planted_locations,
                    "description": "Canary bait credential authentication triggered",
                },
            )
            global_collector.collect(canary_event)

            # 2. Cross-Service Lateral Reuse Detection
            reuse_event = None
            if cred.origin_asset and cred.origin_asset != target_asset:
                reuse_event = SecurityEvent(
                    asset_id=target_asset,
                    event_type=EventType.CREDENTIAL_REUSE.value,
                    source_ip=src_ip,
                    source_port=src_port,
                    username=username,
                    protocol=protocol,
                    timestamp=now_iso,
                    status=EventStatus.DETECTED.value,
                    metadata={
                        "alert_priority": "CRITICAL",
                        "attack_stage": "Lateral Movement / Cross-Service Credential Reuse",
                        "origin_asset": cred.origin_asset,
                        "target_asset": target_asset,
                        "indicator": f"Bait credential '{username}' seeded on {cred.origin_asset} was reused on {target_asset}",
                        "usage_sequence_length": len(cred.usage_history),
                    },
                )
                global_collector.collect(reuse_event)
                logger.warning(
                    "LATERAL MOVEMENT DETECTED: Credential '%s' (origin: %s) reused on %s from %s",
                    username,
                    cred.origin_asset,
                    target_asset,
                    src_ip,
                )

            return True, canary_event, reuse_event

    def get_all(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [c.to_dict(include_raw=False) for c in self._credentials.values()]

    def count(self) -> int:
        with self._lock:
            return len(self._credentials)


# Global singleton instance
global_registry = CredentialRegistry()
