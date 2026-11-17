"""Centralized Deceptive Asset Management Registry.

Manages all deception assets across the enterprise:
- Honeypot network services (ssh-001, ftp-001, web-001, db-001)
- Fake API keys & cloud credentials (AWS, GCP, Azure tokens)
- Decoy configuration files & environment files (.env, database.cfg)
- Fake database connection strings
- Decoy documents & honeyfiles
- Fake internal service endpoints

Guarantees:
- Unique asset IDs and strict tenant attribution.
- Zero exposure of actual cloud or production credentials (purely fictional bait).
- Automatic event generation and seamless routing into the central event collection pipeline.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from threading import Lock
from typing import Any, Dict, List, Optional
import uuid

from pydantic import BaseModel, Field

from collector.event_collector import global_collector
from shared.config import settings
from shared.event_schema import EventStatus, EventType, SecurityEvent
from shared.logger import get_logger

logger = get_logger("AssetRegistry")


class AssetStatus(str, Enum):
    ACTIVE = "active"
    TRIGGERED = "triggered"
    RETIRED = "retired"


class AssetType(str, Enum):
    HONEYPOT = "honeypot"
    API_KEY = "api_key"
    CLOUD_CREDENTIAL = "cloud_credential"
    CONFIG_FILE = "config_file"
    DB_CONNECTION_STRING = "db_connection_string"
    ENV_FILE = "env_file"
    DECOY_DOCUMENT = "decoy_document"
    SERVICE_ENDPOINT = "service_endpoint"
    HONEYTOKEN = "honeytoken"


class DeceptiveAsset(BaseModel):
    """Standardized metadata representation of any deceptive asset."""

    asset_id: str = Field(
        ...,
        description="Unique identifier for the deceptive asset (e.g., ssh-001, apikey-001)",
    )
    tenant_id: str = Field(
        ...,
        description="Tenant identifier managing or owning this deceptive asset",
    )
    asset_type: str = Field(
        ...,
        description="Classification of asset: honeypot, api_key, cloud_credential, config_file, etc.",
    )
    asset_name: str = Field(
        ...,
        description="Human-readable asset descriptor",
    )
    service_type: str = Field(
        ...,
        description="Associated service or protocol type (ssh, ftp, web, database, aws, gcp, etc.)",
    )
    deployment_location: str = Field(
        ...,
        description="Identifiable deployment target (e.g., network:0.0.0.0:2222, web:/configuration/aws.env)",
    )
    status: str = Field(
        default=AssetStatus.ACTIVE.value,
        description="Operational status: active, triggered, retired",
    )
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        description="ISO 8601 UTC creation timestamp",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary safe metadata describing decoy properties",
    )
    fictional_payload: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Purely fictional, non-functional bait contents (e.g., fake key string, decoy URL)",
    )


class AssetRegistry:
    """Thread-safe centralized registry for all deceptive assets."""

    def __init__(self, tenant_id: Optional[str] = None):
        self._lock = Lock()
        self.default_tenant = tenant_id or settings.DEFAULT_TENANT_ID
        self._assets: Dict[str, DeceptiveAsset] = {}
        self._seed_default_assets()

    def _seed_default_assets(self) -> None:
        """Seed baseline honeypot services and standard decoy assets."""
        defaults = [
            # 1. Primary Network Honeypots
            DeceptiveAsset(
                asset_id=settings.SSH_ASSET_ID,
                tenant_id=self.default_tenant,
                asset_type=AssetType.HONEYPOT.value,
                asset_name="Apex Financial SSH Interactive Shell Decoy",
                service_type="ssh",
                deployment_location=f"network:{settings.SSH_LISTEN_HOST}:{settings.SSH_LISTEN_PORT}",
                metadata={"hostname": settings.SSH_HOSTNAME, "os": "Ubuntu 22.04 LTS"},
            ),
            DeceptiveAsset(
                asset_id=settings.FTP_ASSET_ID,
                tenant_id=self.default_tenant,
                asset_type=AssetType.HONEYPOT.value,
                asset_name="Corp Storage Node 02 Decoy FTP Server",
                service_type="ftp",
                deployment_location=f"network:{settings.FTP_LISTEN_HOST}:{settings.FTP_LISTEN_PORT}",
                metadata={"server_name": settings.FTP_SERVER_NAME, "version": "vsftpd 3.0.3"},
            ),
            DeceptiveAsset(
                asset_id=settings.WEB_ASSET_ID,
                tenant_id=self.default_tenant,
                asset_type=AssetType.HONEYPOT.value,
                asset_name="Apex Internal Management System Web Portal",
                service_type="web",
                deployment_location=f"network:{settings.WEB_LISTEN_HOST}:{settings.WEB_LISTEN_PORT}",
                metadata={"portal_name": settings.WEB_PORTAL_NAME, "framework": "FastAPI"},
            ),
            DeceptiveAsset(
                asset_id=settings.DB_ASSET_ID,
                tenant_id=self.default_tenant,
                asset_type=AssetType.HONEYPOT.value,
                asset_name="Corporate Finance Database Cluster Decoy",
                service_type="database",
                deployment_location=f"network:{settings.DB_PG_LISTEN_HOST}:{settings.DB_PG_LISTEN_PORT},{settings.DB_MYSQL_LISTEN_PORT}",
                metadata={"cluster_name": settings.DB_SERVER_NAME, "dialects": ["postgresql", "mysql"]},
            ),
            # 2. Deceptive Cloud & API Tokens
            DeceptiveAsset(
                asset_id="apikey-aws-001",
                tenant_id=self.default_tenant,
                asset_type=AssetType.API_KEY.value,
                asset_name="AWS Production ReadOnly IAM Key",
                service_type="aws",
                deployment_location="web:/configuration/aws_keys.env",
                fictional_payload={
                    "access_key_id": "AKIAIOSFODNN7EXAMPLE",
                    "account_alias": "apex-prod-billing",
                    "warning": "FICTIONAL HONEYTOKEN - ACCESS IS LOGGED",
                },
            ),
            DeceptiveAsset(
                asset_id="cloudcred-gcp-001",
                tenant_id=self.default_tenant,
                asset_type=AssetType.CLOUD_CREDENTIAL.value,
                asset_name="GCP Cloud Storage Auditor Service Account",
                service_type="gcp",
                deployment_location="ssh:/home/finance_admin/.bash_history",
                fictional_payload={
                    "client_email": "sa-auditor@apex-prod-2026.iam.gserviceaccount.com",
                    "project_id": "apex-financial-2026",
                },
            ),
            # 3. Decoy Configurations & Documents
            DeceptiveAsset(
                asset_id="config-db-001",
                tenant_id=self.default_tenant,
                asset_type=AssetType.DB_CONNECTION_STRING.value,
                asset_name="PostgreSQL Master Replica Connection String",
                service_type="database",
                deployment_location="ftp:/backups/finance/db_migration_notes.txt",
                fictional_payload={
                    "connection_uri": "postgresql://database_root:DBroot@2026@db-cluster.corp.internal:5432/corporate_finance",
                },
            ),
            DeceptiveAsset(
                asset_id="doc-exec-comp-001",
                tenant_id=self.default_tenant,
                asset_type=AssetType.DECOY_DOCUMENT.value,
                asset_name="Executive Compensation Q4 2025 Audit Report",
                service_type="web",
                deployment_location="web:/finance/executive_compensation_q4_2025.pdf",
                metadata={"classification": "CONFIDENTIAL - BOARD ONLY"},
            ),
            DeceptiveAsset(
                asset_id="endpoint-internal-001",
                tenant_id=self.default_tenant,
                asset_type=AssetType.SERVICE_ENDPOINT.value,
                asset_name="Internal Payroll Microservice Endpoint",
                service_type="web",
                deployment_location="http://payroll-api.corp.internal:9090/v1/employees",
                metadata={"purpose": "Simulated REST endpoint decoy"},
            ),
        ]

        for asset in defaults:
            self._assets[asset.asset_id] = asset

    def register(self, asset: DeceptiveAsset) -> DeceptiveAsset:
        """Register a new deceptive asset.
        
        Raises:
            ValueError if asset_id is blank, tenant_id is blank, or asset_id already exists.
        """
        if not asset.asset_id or not asset.asset_id.strip():
            raise ValueError("Asset ID cannot be empty")
        if not asset.tenant_id or not asset.tenant_id.strip():
            raise ValueError("Tenant ID cannot be empty")

        with self._lock:
            clean_id = asset.asset_id.strip()
            if clean_id in self._assets:
                raise ValueError(f"Deceptive asset with ID '{clean_id}' is already registered")

            self._assets[clean_id] = asset
            logger.info(
                "Registered deceptive asset [%s] type=%s tenant=%s loc=%s",
                clean_id,
                asset.asset_type,
                asset.tenant_id,
                asset.deployment_location,
            )
            return asset

    def get(self, asset_id: str) -> Optional[DeceptiveAsset]:
        """Fetch asset by ID."""
        with self._lock:
            return self._assets.get(asset_id)

    def get_by_tenant(self, tenant_id: str) -> List[DeceptiveAsset]:
        """Fetch all deceptive assets belonging to a tenant."""
        with self._lock:
            return [a for a in self._assets.values() if a.tenant_id == tenant_id]

    def get_by_type(self, asset_type: str) -> List[DeceptiveAsset]:
        """Fetch all deceptive assets of a specific type."""
        with self._lock:
            return [a for a in self._assets.values() if a.asset_type == asset_type]

    def get_by_service(self, service_type: str) -> List[DeceptiveAsset]:
        """Fetch all deceptive assets associated with a service."""
        with self._lock:
            return [a for a in self._assets.values() if a.service_type.lower() == service_type.lower()]

    def list_all(self) -> List[DeceptiveAsset]:
        """Return a copy of all registered assets."""
        with self._lock:
            return list(self._assets.values())

    def count(self) -> int:
        """Total count of registered assets."""
        with self._lock:
            return len(self._assets)

    def trigger_asset_access(
        self,
        asset_id: str,
        source_ip: str,
        source_port: Optional[int] = None,
        username: Optional[str] = None,
        trigger_type: str = "asset_access",
        details: Optional[Dict[str, Any]] = None,
        severity: str = "high",
        tenant_id: Optional[str] = None,
        event_id: Optional[str] = None,
    ) -> SecurityEvent:
        """Trigger access or discovery of a deceptive asset and inject into event pipeline.
        
        Args:
            asset_id: Target deceptive asset identifier
            source_ip: Attacker/client IP address
            source_port: Client port if available
            username: Username attempting access if available
            trigger_type: Interaction type (e.g. key_leak_probe, file_download, endpoint_scan)
            details: Contextual details (passwords redacted automatically)
            severity: Severity rating (low, medium, high, critical)
            tenant_id: Tenant override (verified against asset tenant if provided)
            event_id: Optional explicit UUID for idempotency
            
        Returns:
            Normalized SecurityEvent dispatched to global collector.
        """
        with self._lock:
            asset = self._assets.get(asset_id)
            if not asset:
                raise ValueError(f"Deceptive asset '{asset_id}' not found in registry")

            effective_tenant = tenant_id or asset.tenant_id
            if tenant_id and tenant_id != asset.tenant_id:
                raise ValueError(
                    f"Cross-tenant mismatch: provided tenant '{tenant_id}' does not own asset '{asset.tenant_id}'"
                )

            asset.status = AssetStatus.TRIGGERED.value

        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Sanitize credentials/passwords from details
        safe_details: Dict[str, Any] = {}
        if details:
            for k, v in details.items():
                if "password" in k.lower() or "secret" in k.lower():
                    safe_details[f"{k}_length"] = len(str(v)) if v is not None else 0
                else:
                    safe_details[k] = v

        safe_details.update({
            "asset_id": asset.asset_id,
            "asset_type": asset.asset_type,
            "asset_name": asset.asset_name,
            "deployment_location": asset.deployment_location,
            "trigger_type": trigger_type,
            "tenant_id": effective_tenant,
        })

        protocol = asset.service_type.upper() if asset.service_type else "CUSTOM"

        event = SecurityEvent(
            event_id=event_id or str(uuid.uuid4()),
            asset_id=asset.asset_id,
            tenant_id=effective_tenant,
            honeytoken_id=asset.asset_id,
            trigger_type=trigger_type,
            severity=severity,
            source_service=asset.service_type,
            event_type=EventType.HONEYTOKEN_TRIGGER.value,
            source_ip=source_ip,
            source_port=source_port,
            username=username,
            protocol=protocol,
            timestamp=now_iso,
            status=EventStatus.DETECTED.value,
            event_details=safe_details,
            metadata=dict(safe_details),
        )

        global_collector.collect(event)
        logger.warning(
            "DECEPTIVE ASSET TRIGGERED: [%s] name='%s' type=%s tenant=%s from %s",
            asset.asset_id, asset.asset_name, asset.asset_type, effective_tenant, source_ip
        )
        return event

    def validate_asset_ownership(self, asset_id: str, tenant_id: str) -> bool:
        """Verify whether an asset exists and is strictly owned by the specified tenant."""
        with self._lock:
            asset = self._assets.get(asset_id)
            if not asset:
                return False
            return asset.tenant_id == tenant_id

    def filter_events_by_tenant(
        self,
        events: List[SecurityEvent],
        tenant_id: str,
    ) -> List[SecurityEvent]:
        """Strictly isolate events by tenant ID to prevent cross-tenant data leakage."""
        if not tenant_id or not tenant_id.strip():
            return []
        return [e for e in events if getattr(e, "tenant_id", None) == tenant_id]

    def validate_event_tenant_isolation(
        self,
        event: SecurityEvent,
        expected_tenant_id: str,
    ) -> bool:
        """Validate that an event belongs strictly to the expected tenant and its asset belongs to that tenant."""
        if not event or event.tenant_id != expected_tenant_id:
            return False
        with self._lock:
            asset = self._assets.get(event.asset_id)
            if asset and asset.tenant_id != expected_tenant_id:
                return False
        return True


# Global singleton instance
global_asset_registry = AssetRegistry()
