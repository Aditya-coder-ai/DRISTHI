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
import uuid
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
        tenant_id: Optional[str] = None,
        honeytoken_id: Optional[str] = None,
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
        self.tenant_id = tenant_id or settings.DEFAULT_TENANT_ID
        self.honeytoken_id = honeytoken_id or f"htk-{username}"

    def verify_password(self, password_attempt: str) -> bool:
        """Verify password without exposing plaintext in logs."""
        attempt_hash = hashlib.sha256(password_attempt.encode("utf-8")).hexdigest()
        return secrets.compare_digest(self.password_hash, attempt_hash)

    def to_dict(self, include_raw: bool = False) -> Dict[str, Any]:
        data = {
            "credential_id": self.credential_id,
            "honeytoken_id": self.honeytoken_id,
            "tenant_id": self.tenant_id,
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
                            cid = item.get("credential_id") or f"cred-{item['username']}"
                            cred = BaitCredential(
                                credential_id=cid,
                                username=item["username"],
                                password=item.get("password", ""),
                                origin_asset=item.get("asset", "unknown"),
                                description=item.get("description", ""),
                                planted_locations=[item.get("type", "generic")],
                                tenant_id=item.get("tenant_id", settings.DEFAULT_TENANT_ID),
                                honeytoken_id=item.get("honeytoken_id", f"htk-{item['username']}"),
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
                tenant_id=settings.DEFAULT_TENANT_ID,
                honeytoken_id=f"htk-{user}",
            )

    def register(
        self,
        username: str,
        password: str,
        origin_asset: str,
        planted_locations: Optional[List[str]] = None,
        description: str = "",
        tenant_id: Optional[str] = None,
        honeytoken_id: Optional[str] = None,
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
                tenant_id=tenant_id or settings.DEFAULT_TENANT_ID,
                honeytoken_id=honeytoken_id or f"htk-{username}",
            )
            self._credentials[username] = cred
            logger.info("Registered new bait credential [%s] for %s (tenant: %s)", username, origin_asset, cred.tenant_id)
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
                tenant_id=existing.tenant_id,
                honeytoken_id=f"htk-{username}-rot-{int(time.time())}",
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
        tenant_id: Optional[str] = None,
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

            active_tenant = tenant_id or cred.tenant_id or settings.DEFAULT_TENANT_ID

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
                "tenant_id": active_tenant,
            }
            cred.usage_history.append(usage_record)

            # 1. CANARY_TRIGGERED Event
            canary_event = SecurityEvent(
                asset_id=target_asset,
                tenant_id=active_tenant,
                honeytoken_id=cred.honeytoken_id or cred.credential_id,
                trigger_type="credential_use",
                severity="critical",
                source_service=protocol.lower() if protocol else "unknown",
                event_type=EventType.CANARY_TRIGGERED.value,
                source_ip=src_ip,
                source_port=src_port,
                username=username,
                protocol=protocol,
                timestamp=now_iso,
                status=EventStatus.DETECTED.value,
                event_details={
                    "alert_priority": "CRITICAL",
                    "credential_id": cred.credential_id,
                    "honeytoken_id": cred.honeytoken_id or cred.credential_id,
                    "origin_asset": cred.origin_asset,
                    "target_asset": target_asset,
                    "trigger_type": "credential_use",
                    "trigger_count": cred.trigger_count,
                    "planted_locations": cred.planted_locations,
                    "description": "Canary bait credential authentication triggered",
                },
                metadata={
                    "alert_priority": "CRITICAL",
                    "credential_id": cred.credential_id,
                    "honeytoken_id": cred.honeytoken_id or cred.credential_id,
                    "origin_asset": cred.origin_asset,
                    "target_asset": target_asset,
                    "trigger_type": "credential_use",
                    "tenant_id": active_tenant,
                    "trigger_count": cred.trigger_count,
                    "planted_locations": cred.planted_locations,
                    "description": "Canary bait credential authentication triggered",
                    "canary_triggered": True,
                },
            )
            global_collector.collect(canary_event)

            # 2. Cross-Service Lateral Reuse Detection
            reuse_event = None
            if cred.origin_asset and cred.origin_asset != target_asset:
                reuse_event = SecurityEvent(
                    asset_id=target_asset,
                    tenant_id=active_tenant,
                    honeytoken_id=cred.honeytoken_id or cred.credential_id,
                    trigger_type="credential_reuse",
                    severity="critical",
                    source_service=protocol.lower() if protocol else "unknown",
                    event_type=EventType.CREDENTIAL_REUSE.value,
                    source_ip=src_ip,
                    source_port=src_port,
                    username=username,
                    protocol=protocol,
                    timestamp=now_iso,
                    status=EventStatus.DETECTED.value,
                    event_details={
                        "alert_priority": "CRITICAL",
                        "attack_stage": "Lateral Movement / Cross-Service Credential Reuse",
                        "credential_id": cred.credential_id,
                        "honeytoken_id": cred.honeytoken_id or cred.credential_id,
                        "origin_asset": cred.origin_asset,
                        "target_asset": target_asset,
                        "trigger_type": "credential_reuse",
                        "indicator": f"Bait credential '{username}' seeded on {cred.origin_asset} was reused on {target_asset}",
                        "usage_sequence_length": len(cred.usage_history),
                    },
                    metadata={
                        "alert_priority": "CRITICAL",
                        "attack_stage": "Lateral Movement / Cross-Service Credential Reuse",
                        "credential_id": cred.credential_id,
                        "honeytoken_id": cred.honeytoken_id or cred.credential_id,
                        "origin_asset": cred.origin_asset,
                        "target_asset": target_asset,
                        "trigger_type": "credential_reuse",
                        "tenant_id": active_tenant,
                        "indicator": f"Bait credential '{username}' seeded on {cred.origin_asset} was reused on {target_asset}",
                        "usage_sequence_length": len(cred.usage_history),
                        "credential_reuse": True,
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

    def trigger_honeytoken(
        self,
        honeytoken_id: str,
        asset_id: str,
        trigger_type: str,
        source_ip: str,
        source_port: Optional[int] = None,
        protocol: str = "CUSTOM",
        tenant_id: Optional[str] = None,
        username: Optional[str] = None,
        severity: str = "high",
        details: Optional[Dict[str, Any]] = None,
        event_id: Optional[str] = None,
    ) -> SecurityEvent:
        """Explicitly trigger a honeytoken and route through the central event pipeline.
        
        Guarantees:
        - Strict tenant and asset association
        - Normalized SecurityEvent schema
        - Plaintext password redaction
        - Automatic deduplication via global collector
        """
        active_tenant = tenant_id or settings.DEFAULT_TENANT_ID
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        
        # Redact any passwords if present in details
        clean_details: Dict[str, Any] = {}
        if details:
            for k, v in details.items():
                if "password" in k.lower() or "secret" in k.lower():
                    clean_details[f"{k}_length"] = len(str(v)) if v is not None else 0
                else:
                    clean_details[k] = v

        clean_details.setdefault("honeytoken_id", honeytoken_id)
        clean_details.setdefault("trigger_type", trigger_type)
        clean_details.setdefault("asset_id", asset_id)
        clean_details.setdefault("tenant_id", active_tenant)

        event = SecurityEvent(
            event_id=event_id or str(uuid.uuid4()),
            asset_id=asset_id,
            tenant_id=active_tenant,
            honeytoken_id=honeytoken_id,
            trigger_type=trigger_type,
            severity=severity,
            source_service=protocol.lower() if protocol else "unknown",
            event_type=EventType.HONEYTOKEN_TRIGGER.value,
            source_ip=source_ip,
            source_port=source_port,
            username=username,
            protocol=protocol,
            timestamp=now_iso,
            status=EventStatus.DETECTED.value,
            event_details=clean_details,
            metadata=dict(clean_details),
        )

        global_collector.collect(event)
        logger.warning(
            "HONEYTOKEN TRIGGERED: [%s] asset=%s tenant=%s type=%s ip=%s",
            honeytoken_id, asset_id, active_tenant, trigger_type, source_ip
        )
        return event

    def get_all(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [c.to_dict(include_raw=False) for c in self._credentials.values()]

    def count(self) -> int:
        with self._lock:
            return len(self._credentials)


# Global singleton instance
global_registry = CredentialRegistry()

