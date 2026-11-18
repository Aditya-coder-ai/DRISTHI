"""Honeytoken lifecycle management schema and baseline seeding

Revision ID: 0004_honeytoken_lifecycle_management
Revises: 0003_deceptive_asset_registry
Create Date: 2026-11-18 18:50:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = '0004_honeytoken_lifecycle_management'
down_revision: Union[str, None] = '0003_deceptive_asset_registry'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

JSONType = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    # 1. Create honeytokens table
    op.create_table(
        'honeytokens',
        sa.Column('token_id', sa.String(length=64), nullable=False),
        sa.Column('tenant_id', sa.String(length=64), nullable=False),
        sa.Column('asset_id', sa.String(length=64), nullable=False),
        sa.Column('token_type', sa.String(length=32), nullable=False),
        sa.Column('name', sa.String(length=128), nullable=False),
        sa.Column('description', sa.String(length=256), nullable=True),
        sa.Column('token_value_masked', sa.String(length=128), nullable=False),
        sa.Column('token_hash', sa.String(length=64), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='active'),
        sa.Column('metadata', JSONType, nullable=False, server_default='{}'),
        sa.Column('trigger_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('last_triggered_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.current_timestamp()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.current_timestamp()),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.tenant_id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['asset_id'], ['deceptive_assets.asset_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('token_id')
    )

    op.create_index('ix_honeytokens_token_id', 'honeytokens', ['token_id'])
    op.create_index('ix_honeytokens_tenant_id', 'honeytokens', ['tenant_id'])
    op.create_index('ix_honeytokens_asset_id', 'honeytokens', ['asset_id'])
    op.create_index('ix_honeytokens_token_type', 'honeytokens', ['token_type'])
    op.create_index('ix_honeytokens_token_hash', 'honeytokens', ['token_hash'])
    op.create_index('ix_honeytokens_status', 'honeytokens', ['status'])
    op.create_index('ix_honeytokens_tenant_status', 'honeytokens', ['tenant_id', 'status'])
    op.create_index('ix_honeytokens_tenant_asset', 'honeytokens', ['tenant_id', 'asset_id'])
    op.create_index('ix_honeytokens_tenant_type', 'honeytokens', ['tenant_id', 'token_type'])

    # 2. Seed baseline honeytokens for default tenant
    op.execute("""
        INSERT INTO honeytokens (
            token_id, tenant_id, asset_id, token_type, name, description,
            token_value_masked, token_hash, status, metadata, trigger_count
        ) VALUES
        (
            'htk-aws-prod-001', 'tenant-apex-001', 'canary-token-aws-01', 'aws_iam',
            'Production Root AWS Canary Key', 'Embedded in fake /backups/credentials.env',
            'AKIA-CANARY-****-8F92', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            'active', '{"planted_location": "/backups/credentials.env", "key_role": "admin"}', 0
        ),
        (
            'htk-ssh-backup-001', 'tenant-apex-001', 'ssh-001', 'ssh_credential',
            'Decoy SSH Backup Service Key', 'Planted in ~/.ssh/authorized_keys bait file',
            'canary_svc_****_2026', 'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb',
            'active', '{"planted_location": "/home/backup/.ssh/id_rsa.pub", "service": "ssh"}', 0
        )
    """)


def downgrade() -> None:
    op.drop_index('ix_honeytokens_tenant_type', table_name='honeytokens')
    op.drop_index('ix_honeytokens_tenant_asset', table_name='honeytokens')
    op.drop_index('ix_honeytokens_tenant_status', table_name='honeytokens')
    op.drop_index('ix_honeytokens_status', table_name='honeytokens')
    op.drop_index('ix_honeytokens_token_hash', table_name='honeytokens')
    op.drop_index('ix_honeytokens_token_type', table_name='honeytokens')
    op.drop_index('ix_honeytokens_asset_id', table_name='honeytokens')
    op.drop_index('ix_honeytokens_tenant_id', table_name='honeytokens')
    op.drop_index('ix_honeytokens_token_id', table_name='honeytokens')
    op.drop_table('honeytokens')
