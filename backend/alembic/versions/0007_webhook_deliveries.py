"""0007 - Webhook Deliveries

Creates webhook_deliveries table for tracking external webhook notifications,
delivery attempts, responses, and retry states.

Revision ID: 0007_webhook_deliveries
Revises: 0006_integration_configurations
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "0007_webhook_deliveries"
down_revision: Union[str, None] = "0006_integration_configurations"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

JSONType = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    # 1. Create webhook_deliveries table
    op.create_table(
        "webhook_deliveries",
        sa.Column("delivery_id", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(length=64), sa.ForeignKey("tenants.tenant_id", ondelete="CASCADE"), nullable=False),
        sa.Column("integration_id", sa.String(length=64), sa.ForeignKey("integration_configs.integration_id", ondelete="CASCADE"), nullable=False),
        sa.Column("event_id", sa.String(length=64), sa.ForeignKey("attack_events.event_id", ondelete="CASCADE"), nullable=False),
        sa.Column("destination_url", sa.String(length=512), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("payload", JSONType, nullable=False, server_default="{}"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="pending"),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("response_body", sa.String(length=1024), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="3"),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_retry_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_message", sa.String(length=512), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.current_timestamp()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.current_timestamp()),
    )

    # 2. Indexes
    op.create_index("ix_deliveries_delivery_id", "webhook_deliveries", ["delivery_id"])
    op.create_index("ix_deliveries_tenant_id", "webhook_deliveries", ["tenant_id"])
    op.create_index("ix_deliveries_integration_id", "webhook_deliveries", ["integration_id"])
    op.create_index("ix_deliveries_event_id", "webhook_deliveries", ["event_id"])
    op.create_index("ix_deliveries_event_type", "webhook_deliveries", ["event_type"])
    op.create_index("ix_deliveries_status", "webhook_deliveries", ["status"])
    op.create_index("ix_deliveries_tenant_status", "webhook_deliveries", ["tenant_id", "status"])
    op.create_index("ix_deliveries_tenant_integration", "webhook_deliveries", ["tenant_id", "integration_id"])
    op.create_index("ix_deliveries_event_integration", "webhook_deliveries", ["event_id", "integration_id"])


def downgrade() -> None:
    op.drop_index("ix_deliveries_event_integration", table_name="webhook_deliveries")
    op.drop_index("ix_deliveries_tenant_integration", table_name="webhook_deliveries")
    op.drop_index("ix_deliveries_tenant_status", table_name="webhook_deliveries")
    op.drop_index("ix_deliveries_status", table_name="webhook_deliveries")
    op.drop_index("ix_deliveries_event_type", table_name="webhook_deliveries")
    op.drop_index("ix_deliveries_event_id", table_name="webhook_deliveries")
    op.drop_index("ix_deliveries_integration_id", table_name="webhook_deliveries")
    op.drop_index("ix_deliveries_tenant_id", table_name="webhook_deliveries")
    op.drop_index("ix_deliveries_delivery_id", table_name="webhook_deliveries")
    op.drop_table("webhook_deliveries")
