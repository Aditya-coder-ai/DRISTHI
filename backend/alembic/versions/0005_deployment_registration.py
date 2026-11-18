"""0005 - Deployment Registration

Creates the deployments table for tracking deployment lifecycle of deceptive assets.
Seeds baseline deployment records for the 5 default honeypot assets.

Revision ID: 0005_deployment_registration
Revises: 0004_honeytoken_lifecycle_management
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "0005_deployment_registration"
down_revision: Union[str, None] = "0004_honeytoken_lifecycle_management"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

JSONType = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    # 1. Create deployments table
    op.create_table(
        "deployments",
        sa.Column("deployment_id", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("asset_id", sa.String(length=64), sa.ForeignKey("deceptive_assets.asset_id", ondelete="CASCADE"), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), sa.ForeignKey("tenants.tenant_id", ondelete="CASCADE"), nullable=False),
        sa.Column("asset_type", sa.String(length=32), nullable=False),
        sa.Column("environment", sa.String(length=32), nullable=False, server_default="production"),
        sa.Column("version", sa.String(length=64), nullable=True),
        sa.Column("hostname", sa.String(length=128), nullable=True),
        sa.Column("ip_address", sa.String(length=45), nullable=True),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="registered"),
        sa.Column("registered_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.current_timestamp()),
        sa.Column("last_heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deploy_metadata", JSONType, nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.current_timestamp()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.current_timestamp()),
    )

    # 2. Indexes
    op.create_index("ix_deployments_deployment_id", "deployments", ["deployment_id"])
    op.create_index("ix_deployments_asset_id", "deployments", ["asset_id"])
    op.create_index("ix_deployments_tenant_id", "deployments", ["tenant_id"])
    op.create_index("ix_deployments_asset_type", "deployments", ["asset_type"])
    op.create_index("ix_deployments_status", "deployments", ["status"])
    op.create_index("ix_deployments_tenant_type", "deployments", ["tenant_id", "asset_type"])
    op.create_index("ix_deployments_tenant_status", "deployments", ["tenant_id", "status"])
    op.create_index("ix_deployments_asset_tenant", "deployments", ["asset_id", "tenant_id"])

    # 3. Seed baseline deployment records for the 5 default honeypot assets
    op.execute("""
        INSERT INTO deployments (
            deployment_id, asset_id, tenant_id, asset_type, environment,
            version, hostname, port, status, deploy_metadata
        ) VALUES
        (
            'deploy-ssh-prod-01', 'ssh-001', 'tenant-apex-001', 'ssh_honeypot', 'production',
            '1.0.0', 'finance-server.corp.internal', 2222, 'active', '{}'
        ),
        (
            'deploy-ftp-prod-01', 'ftp-001', 'tenant-apex-001', 'ftp_honeypot', 'production',
            '1.0.0', 'Corp-Storage-Node-02', 2121, 'active', '{}'
        ),
        (
            'deploy-web-prod-01', 'web-001', 'tenant-apex-001', 'http_honeypot', 'production',
            '1.0.0', 'web-admin.corp.internal', 8080, 'active', '{}'
        ),
        (
            'deploy-db-prod-01', 'db-001', 'tenant-apex-001', 'database_honeypot', 'production',
            '1.0.0', 'db-cluster.corp.internal', 5432, 'active', '{}'
        ),
        (
            'deploy-token-aws-01', 'canary-token-aws-01', 'tenant-apex-001', 'honeytoken', 'production',
            '1.0.0', NULL, NULL, 'active', '{}'
        )
    """)


def downgrade() -> None:
    op.drop_index("ix_deployments_asset_tenant", table_name="deployments")
    op.drop_index("ix_deployments_tenant_status", table_name="deployments")
    op.drop_index("ix_deployments_tenant_type", table_name="deployments")
    op.drop_index("ix_deployments_status", table_name="deployments")
    op.drop_index("ix_deployments_asset_type", table_name="deployments")
    op.drop_index("ix_deployments_tenant_id", table_name="deployments")
    op.drop_index("ix_deployments_asset_id", table_name="deployments")
    op.drop_index("ix_deployments_deployment_id", table_name="deployments")
    op.drop_table("deployments")
