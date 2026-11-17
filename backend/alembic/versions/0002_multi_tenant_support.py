"""Multi-tenant schema support and data backfill

Revision ID: 0002_multi_tenant_support
Revises: 0001_initial_schema
Create Date: 2026-11-17 19:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '0002_multi_tenant_support'
down_revision: Union[str, None] = '0001_initial_schema'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create tenants table
    op.create_table(
        'tenants',
        sa.Column('tenant_id', sa.String(length=64), nullable=False),
        sa.Column('name', sa.String(length=128), nullable=False),
        sa.Column('description', sa.String(length=256), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.current_timestamp()),
        sa.PrimaryKeyConstraint('tenant_id')
    )
    op.create_index('ix_tenants_tenant_id', 'tenants', ['tenant_id'])

    # 2. Seed default tenant
    op.execute(
        "INSERT INTO tenants (tenant_id, name, description, is_active) "
        "VALUES ('tenant-apex-001', 'Apex Financial Group', 'Default enterprise tenant', 1)"
    )

    # 3. Add tenant_id to attack_events
    with op.batch_alter_table('attack_events') as batch_op:
        batch_op.add_column(sa.Column('tenant_id', sa.String(length=64), nullable=False, server_default='tenant-apex-001'))
        batch_op.create_index('ix_attack_events_tenant_id', ['tenant_id'])
        batch_op.create_index('ix_events_tenant_time', ['tenant_id', 'timestamp'])

    # 4. Add tenant_id to attacker_sessions
    with op.batch_alter_table('attacker_sessions') as batch_op:
        batch_op.add_column(sa.Column('tenant_id', sa.String(length=64), nullable=False, server_default='tenant-apex-001'))
        batch_op.create_index('ix_attacker_sessions_tenant_id', ['tenant_id'])
        batch_op.create_index('ix_sessions_tenant_ip', ['tenant_id', 'source_ip'])
        batch_op.create_index('ix_sessions_tenant_last_seen', ['tenant_id', 'last_seen'])

    # 5. Add tenant_id to attacker_profiles and update uniqueness
    with op.batch_alter_table('attacker_profiles') as batch_op:
        batch_op.add_column(sa.Column('tenant_id', sa.String(length=64), nullable=False, server_default='tenant-apex-001'))
        batch_op.create_index('ix_attacker_profiles_tenant_id', ['tenant_id'])
        batch_op.create_index('ix_attacker_profiles_tenant_last_seen', ['tenant_id', 'last_seen'])
        batch_op.create_unique_constraint('uq_attacker_tenant_source_ip', ['tenant_id', 'source_ip'])

    # 6. Backfill existing records explicitly
    op.execute("UPDATE attack_events SET tenant_id = 'tenant-apex-001' WHERE tenant_id IS NULL OR tenant_id = ''")
    op.execute("UPDATE attacker_sessions SET tenant_id = 'tenant-apex-001' WHERE tenant_id IS NULL OR tenant_id = ''")
    op.execute("UPDATE attacker_profiles SET tenant_id = 'tenant-apex-001' WHERE tenant_id IS NULL OR tenant_id = ''")


def downgrade() -> None:
    with op.batch_alter_table('attacker_profiles') as batch_op:
        batch_op.drop_constraint('uq_attacker_tenant_source_ip', type_='unique')
        batch_op.drop_index('ix_attacker_profiles_tenant_last_seen')
        batch_op.drop_index('ix_attacker_profiles_tenant_id')
        batch_op.drop_column('tenant_id')

    with op.batch_alter_table('attacker_sessions') as batch_op:
        batch_op.drop_index('ix_sessions_tenant_last_seen')
        batch_op.drop_index('ix_sessions_tenant_ip')
        batch_op.drop_index('ix_attacker_sessions_tenant_id')
        batch_op.drop_column('tenant_id')

    with op.batch_alter_table('attack_events') as batch_op:
        batch_op.drop_index('ix_events_tenant_time')
        batch_op.drop_index('ix_attack_events_tenant_id')
        batch_op.drop_column('tenant_id')

    op.drop_table('tenants')
