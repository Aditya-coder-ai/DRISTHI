"""Initial schema for DRISTHI Central Backend

Revision ID: 0001_initial_schema
Revises: 
Create Date: 2026-11-14 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '0001_initial_schema'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

JSONType = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    # 1. attacker_profiles
    op.create_table(
        'attacker_profiles',
        sa.Column('attacker_id', sa.String(length=64), nullable=False),
        sa.Column('source_ip', sa.String(length=64), nullable=False),
        sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('total_events', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('total_sessions', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('highest_severity', sa.String(length=16), nullable=False, server_default='low'),
        sa.Column('attempted_usernames', JSONType, nullable=False),
        sa.Column('attempted_commands', JSONType, nullable=False),
        sa.Column('services_targeted', JSONType, nullable=False),
        sa.Column('risk_score', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('attacker_id'),
        sa.UniqueConstraint('source_ip')
    )
    op.create_index('ix_attacker_profiles_attacker_id', 'attacker_profiles', ['attacker_id'])
    op.create_index('ix_attacker_profiles_source_ip', 'attacker_profiles', ['source_ip'])
    op.create_index('ix_attacker_profiles_last_seen', 'attacker_profiles', ['last_seen'])

    # 2. attacker_sessions
    op.create_table(
        'attacker_sessions',
        sa.Column('session_id', sa.String(length=64), nullable=False),
        sa.Column('attacker_id', sa.String(length=64), nullable=True),
        sa.Column('source_ip', sa.String(length=64), nullable=False),
        sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('services_accessed', JSONType, nullable=False),
        sa.Column('event_count', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('status', sa.String(length=16), nullable=False, server_default='active'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['attacker_id'], ['attacker_profiles.attacker_id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('session_id')
    )
    op.create_index('ix_attacker_sessions_session_id', 'attacker_sessions', ['session_id'])
    op.create_index('ix_attacker_sessions_source_ip', 'attacker_sessions', ['source_ip'])
    op.create_index('ix_attacker_sessions_status', 'attacker_sessions', ['status'])
    op.create_index('ix_attacker_sessions_last_seen', 'attacker_sessions', ['last_seen'])

    # 3. attack_events
    op.create_table(
        'attack_events',
        sa.Column('event_id', sa.String(length=64), nullable=False),
        sa.Column('session_id', sa.String(length=64), nullable=True),
        sa.Column('source_ip', sa.String(length=64), nullable=False),
        sa.Column('source_port', sa.Integer(), nullable=True),
        sa.Column('source_service', sa.String(length=32), nullable=False),
        sa.Column('asset_id', sa.String(length=64), nullable=False),
        sa.Column('event_type', sa.String(length=64), nullable=False),
        sa.Column('username', sa.String(length=128), nullable=True),
        sa.Column('severity', sa.String(length=16), nullable=False, server_default='low'),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='attempt'),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('activity', JSONType, nullable=False),
        sa.Column('metadata', JSONType, nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['session_id'], ['attacker_sessions.session_id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('event_id')
    )
    op.create_index('ix_attack_events_event_id', 'attack_events', ['event_id'])
    op.create_index('ix_attack_events_source_ip', 'attack_events', ['source_ip'])
    op.create_index('ix_attack_events_source_service', 'attack_events', ['source_service'])
    op.create_index('ix_attack_events_asset_id', 'attack_events', ['asset_id'])
    op.create_index('ix_attack_events_event_type', 'attack_events', ['event_type'])
    op.create_index('ix_attack_events_severity', 'attack_events', ['severity'])
    op.create_index('ix_attack_events_timestamp', 'attack_events', ['timestamp'])
    op.create_index('ix_events_service_severity_time', 'attack_events', ['source_service', 'severity', 'timestamp'])
    op.create_index('ix_events_source_ip_timestamp', 'attack_events', ['source_ip', 'timestamp'])

    # 4. mitre_mappings
    op.create_table(
        'mitre_mappings',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('event_id', sa.String(length=64), nullable=False),
        sa.Column('technique_id', sa.String(length=32), nullable=False),
        sa.Column('technique_name', sa.String(length=128), nullable=False),
        sa.Column('tactic', sa.String(length=64), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='1.0'),
        sa.Column('evidence', sa.Text(), nullable=False),
        sa.Column('mapping_source', sa.String(length=32), nullable=False, server_default='rule_engine'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['event_id'], ['attack_events.event_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_mitre_mappings_event_id', 'mitre_mappings', ['event_id'])
    op.create_index('ix_mitre_mappings_technique_id', 'mitre_mappings', ['technique_id'])


def downgrade() -> None:
    op.drop_table('mitre_mappings')
    op.drop_table('attack_events')
    op.drop_table('attacker_sessions')
    op.drop_table('attacker_profiles')

