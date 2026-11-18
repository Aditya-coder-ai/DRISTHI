"""0006 - Integration Configuration Registry

Creates integration_configs table for managing external Webhooks, SIEM,
and Security Monitoring configurations with encrypted/hashed secrets.

Revision ID: 0006_integration_configurations
Revises: 0005_deployment_registration
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "0006_integration_configurations"
down_revision: Union[str, None] = "0005_deployment_registration"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

JSONType = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    # 1. Create integration_configs table
    op.create_table(
        "integration_configs",
        sa.Column("integration_id", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(length=64), sa.ForeignKey("tenants.tenant_id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("integration_type", sa.String(length=32), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="configured"),
        sa.Column("config_metadata", JSONType, nullable=False, server_default="{}"),
        sa.Column("secret_masked", sa.String(length=128), nullable=True),
        sa.Column("secret_hash", sa.String(length=64), nullable=True),
        sa.Column("secret_storage", sa.String(length=256), nullable=True),
        sa.Column("last_validated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("validation_details", JSONType, nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.current_timestamp()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.current_timestamp()),
    )

    # 2. Indexes
    op.create_index("ix_integrations_integration_id", "integration_configs", ["integration_id"])
    op.create_index("ix_integrations_tenant_id", "integration_configs", ["tenant_id"])
    op.create_index("ix_integrations_type", "integration_configs", ["integration_type"])
    op.create_index("ix_integrations_enabled", "integration_configs", ["enabled"])
    op.create_index("ix_integrations_status", "integration_configs", ["status"])
    op.create_index("ix_integrations_tenant_type", "integration_configs", ["tenant_id", "integration_type"])
    op.create_index("ix_integrations_tenant_enabled", "integration_configs", ["tenant_id", "enabled"])
    op.create_index("ix_integrations_tenant_status", "integration_configs", ["tenant_id", "status"])


def downgrade() -> None:
    op.drop_index("ix_integrations_tenant_status", table_name="integration_configs")
    op.drop_index("ix_integrations_tenant_enabled", table_name="integration_configs")
    op.drop_index("ix_integrations_tenant_type", table_name="integration_configs")
    op.drop_index("ix_integrations_status", table_name="integration_configs")
    op.drop_index("ix_integrations_enabled", table_name="integration_configs")
    op.drop_index("ix_integrations_type", table_name="integration_configs")
    op.drop_index("ix_integrations_tenant_id", table_name="integration_configs")
    op.drop_index("ix_integrations_integration_id", table_name="integration_configs")
    op.drop_table("integration_configs")
