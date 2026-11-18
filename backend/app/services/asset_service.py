"""Centralized Deceptive Asset Management Service."""

from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy.orm import Session

from backend.app.models.asset import DeceptiveAsset
from backend.app.models.deployment import Deployment
from backend.app.schemas.asset import AssetCreate, AssetStatus, AssetType
from backend.app.schemas.deployment import DeploymentStatus


DEFAULT_HONEYPOTS = [
    {
        "asset_id": "ssh-001",
        "name": "Apex Core SSH Gateway",
        "asset_type": AssetType.SSH_HONEYPOT.value,
        "description": "Emulated Cowrie SSH shell service presenting finance-server identity",
        "deployment_id": "deploy-ssh-prod-01",
        "environment": "production",
        "status": AssetStatus.ACTIVE.value,
        "config_metadata": {
            "port": 2222,
            "protocol": "SSH-2.0-OpenSSH_8.9p1",
            "hostname": "finance-server.corp.internal",
            "service": "ssh",
        },
    },
    {
        "asset_id": "ftp-001",
        "name": "Corporate Backup Storage FTP",
        "asset_type": AssetType.FTP_HONEYPOT.value,
        "description": "RFC 959 emulated FTP file server presenting Corp-Storage-Node-02",
        "deployment_id": "deploy-ftp-prod-01",
        "environment": "production",
        "status": AssetStatus.ACTIVE.value,
        "config_metadata": {
            "port": 2121,
            "protocol": "FTP",
            "hostname": "Corp-Storage-Node-02",
            "service": "ftp",
        },
    },
    {
        "asset_id": "web-001",
        "name": "Web Admin Management Portal",
        "asset_type": AssetType.HTTP_HONEYPOT.value,
        "description": "Fictional internal administrative portal presenting web-admin interface",
        "deployment_id": "deploy-web-prod-01",
        "environment": "production",
        "status": AssetStatus.ACTIVE.value,
        "config_metadata": {
            "port": 8080,
            "protocol": "HTTP",
            "hostname": "web-admin.corp.internal",
            "service": "web",
        },
    },
    {
        "asset_id": "db-001",
        "name": "Apex Relational DB Cluster",
        "asset_type": AssetType.DATABASE_HONEYPOT.value,
        "description": "Simulated PostgreSQL & MySQL database deception service",
        "deployment_id": "deploy-db-prod-01",
        "environment": "production",
        "status": AssetStatus.ACTIVE.value,
        "config_metadata": {
            "port_pg": 5432,
            "port_my": 3306,
            "protocol": "PostgreSQL/MySQL",
            "hostname": "db-cluster.corp.internal",
            "service": "database",
        },
    },
    {
        "asset_id": "canary-token-aws-01",
        "name": "Decoy AWS Root Access Key",
        "asset_type": AssetType.HONEYTOKEN.value,
        "description": "Canary cloud access key embedded in fake environment configuration",
        "deployment_id": "deploy-token-aws-01",
        "environment": "production",
        "status": AssetStatus.ACTIVE.value,
        "config_metadata": {
            "key_type": "aws_iam",
            "planted_location": "/backups/credentials.env",
            "trigger_severity": "critical",
        },
    },
]


class AssetService:
    """Manages deceptive asset lifecycle, discovery, and baseline seeding."""

    def __init__(self, db: Session):
        self.db = db

    def seed_default_assets(self, tenant_id: str = "tenant-apex-001") -> List[DeceptiveAsset]:
        """Idempotently registers baseline honeypots and canaries for a tenant."""
        clean_tenant = tenant_id.strip()
        seeded = []
        now = datetime.now(timezone.utc)

        for item in DEFAULT_HONEYPOTS:
            asset_id = item["asset_id"]
            existing = self.db.query(DeceptiveAsset).filter(
                DeceptiveAsset.asset_id == asset_id,
                DeceptiveAsset.tenant_id == clean_tenant,
            ).first()

            if not existing:
                asset = DeceptiveAsset(
                    asset_id=asset_id,
                    tenant_id=clean_tenant,
                    name=item["name"],
                    asset_type=item["asset_type"],
                    description=item["description"],
                    deployment_id=item["deployment_id"],
                    environment=item["environment"],
                    status=item["status"],
                    config_metadata=item["config_metadata"],
                    created_at=now,
                    updated_at=now,
                )
                self.db.add(asset)
                seeded.append(asset)

        if seeded:
            self.db.commit()
            for a in seeded:
                self.db.refresh(a)

        # Idempotently seed corresponding default deployments
        seeded_deployments = []
        for item in DEFAULT_HONEYPOTS:
            dep_id = item.get("deployment_id")
            if dep_id:
                existing_dep = self.db.query(Deployment).filter(
                    Deployment.deployment_id == dep_id,
                    Deployment.tenant_id == clean_tenant,
                ).first()
                if not existing_dep:
                    meta = item.get("config_metadata") or {}
                    dep = Deployment(
                        deployment_id=dep_id,
                        asset_id=item["asset_id"],
                        tenant_id=clean_tenant,
                        asset_type=item["asset_type"],
                        environment=item["environment"],
                        version="1.0.0",
                        hostname=meta.get("hostname"),
                        ip_address=None,
                        port=meta.get("port") or meta.get("port_pg"),
                        status=DeploymentStatus.ACTIVE.value,
                        registered_at=now,
                        last_heartbeat_at=now,
                        deploy_metadata=meta,
                        created_at=now,
                        updated_at=now,
                    )
                    self.db.add(dep)
                    seeded_deployments.append(dep)

        if seeded_deployments:
            self.db.commit()
            for d in seeded_deployments:
                self.db.refresh(d)

        return seeded

    def ensure_asset_registered(
        self,
        asset_id: str,
        tenant_id: str,
        source_service: Optional[str] = None,
    ) -> DeceptiveAsset:
        """Retrieves an asset or auto-provisions a registered entry if previously uncataloged."""
        clean_id = asset_id.strip()
        clean_tenant = tenant_id.strip()

        asset = self.db.query(DeceptiveAsset).filter(
            DeceptiveAsset.asset_id == clean_id,
            DeceptiveAsset.tenant_id == clean_tenant,
        ).first()

        if not asset:
            now = datetime.now(timezone.utc)
            service_type = (source_service or "unknown").lower()
            asset_type = f"{service_type}_honeypot" if service_type in ["ssh", "ftp", "http", "database"] else "honeytoken"
            asset = DeceptiveAsset(
                asset_id=clean_id,
                tenant_id=clean_tenant,
                name=f"Auto-Registered {clean_id}",
                asset_type=asset_type,
                description=f"Auto-cataloged deceptive asset observed from telemetry",
                deployment_id=f"auto-{clean_id}",
                environment="production",
                status=AssetStatus.ACTIVE.value,
                config_metadata={"auto_registered": True, "source_service": service_type},
                created_at=now,
                updated_at=now,
            )
            self.db.add(asset)
            self.db.commit()
            self.db.refresh(asset)

        return asset
