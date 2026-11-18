"""Deceptive asset registry schema and baseline seeding

Revision ID: 0003_deceptive_asset_registry
Revises: 0002_multi_tenant_support
Create Date: 2026-11-18 09:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = '0003_deceptive_asset_registry'
down_revision: Union[str, None] = '0002_multi_tenant_support'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

JSONType = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    # 1. Create deceptive_assets table
    op.create_table(
        'deceptive_assets',
        sa.Column('asset_id', sa.String(length=64), nullable=False),
        sa.Column('tenant_id', sa.String(length=64), nullable=False),
        sa.Column('name', sa.String(length=128), nullable=False),
        sa.Column('asset_type', sa.String(length=32), nullable=False),
        sa.Column('description', sa.String(length=256), nullable=True),
        sa.Column('deployment_id', sa.String(length=64), nullable=True),
        sa.Column('environment', sa.String(length=32), nullable=False, server_default='production'),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='active'),
        sa.Column('config_metadata', JSONType, nullable=False, server_default='{}'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.current_timestamp()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.current_timestamp()),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.tenant_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('asset_id')
    )

    op.create_index('ix_deceptive_assets_asset_id', 'deceptive_assets', ['asset_id'])
    op.create_index('ix_deceptive_assets_tenant_id', 'deceptive_assets', ['tenant_id'])
    op.create_index('ix_assets_tenant_type', 'deceptive_assets', ['tenant_id', 'asset_type'])
    op.create_index('ix_assets_tenant_status', 'deceptive_assets', ['tenant_id', 'status'])

    # 2. Pre-seed default deployed honeypots and canary tokens for default tenant
    op.execute("""
        INSERT INTO deceptive_assets (
            asset_id, tenant_id, name, asset_type, description,
            deployment_id, environment, status, config_metadata
        ) VALUES
        (
            'ssh-001', 'tenant-apex-001', 'Apex Core SSH Gateway', 'ssh_honeypot',
            'Emulated Cowrie SSH shell service presenting finance-server identity',
            'deploy-ssh-prod-01', 'production', 'active',
            '{"port": 2222, "protocol": "SSH-2.0-OpenSSH_8.9p1", "hostname": "finance-server.corp.internal"}'
        ),
        (
            'ftp-001', 'tenant-apex-001', 'Corporate Backup Storage FTP', 'ftp_honeypot',
            'RFC 959 emulated FTP file server presenting Corp-Storage-Node-02',
            'deploy-ftp-prod-01', 'production', 'active',
            '{"port": 2121, "protocol": "FTP", "hostname": "Corp-Storage-Node-02"}'
        ),
        (
            'web-001', 'tenant-apex-001', 'Web Admin Management Portal', 'http_honeypot',
            'Fictional internal administrative portal presenting web-admin interface',
            'deploy-web-prod-01', 'production', 'active',
            '{"port": 8080, "protocol": "HTTP", "hostname": "web-admin.corp.internal"}'
        ),
        (
            'db-001', 'tenant-apex-001', 'Apex Relational DB Cluster', 'database_honeypot',
            'Simulated PostgreSQL & MySQL database deception service',
            'deploy-db-prod-01', 'production', 'active',
            '{"port_pg": 5432, "port_my": 3306, "protocol": "PostgreSQL/MySQL", "hostname": "db-cluster.corp.internal"}'
        ),
        (
            'canary-token-aws-01', 'tenant-apex-001', 'Decoy AWS Root Access Key', 'honeytoken',
            'Canary cloud access key embedded in fake environment configuration',
            'deploy-token-aws-01', 'production', 'active',
            '{"key_type": "aws_iam", "planted_location": "/backups/credentials.env"}'
        )
    """)


def downgrade() -> None:
    op.drop_index('ix_assets_tenant_status', table_name='deceptive_assets')
    op.drop_index('ix_assets_tenant_type', table_name='deceptive_assets')
    op.drop_index('ix_deceptive_assets_tenant_id', table_name='deceptive_assets')
    op.drop_index('ix_deceptive_assets_asset_id', table_name='deceptive_assets')
    op.drop_table('deceptive_assets')
