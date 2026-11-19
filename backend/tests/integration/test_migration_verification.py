"""Test verification for Alembic 0002_multi_tenant_support migration on existing data."""

import os
import shutil
import tempfile
from pathlib import Path
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text


def test_alembic_multi_tenant_migration_clean_backfill():
    """Verify that 0002 migration applies cleanly on top of 0001 schema with pre-existing data."""
    temp_dir = tempfile.mkdtemp()
    db_path = Path(temp_dir) / "migration_test.db"
    db_url = f"sqlite:///{db_path}"

    backend_dir = Path(__file__).resolve().parent.parent.parent
    project_root = backend_dir.parent
    alembic_ini = project_root / "alembic.ini"
    alembic_cfg = Config(str(alembic_ini))
    alembic_cfg.set_main_option("sqlalchemy.url", db_url)
    alembic_cfg.set_main_option("script_location", str(backend_dir / "alembic"))

    try:
        # 1. Upgrade to 0001_initial_schema
        command.upgrade(alembic_cfg, "0001_initial_schema")

        engine = create_engine(db_url)
        with engine.begin() as conn:
            # Insert pre-existing data using 0001 schema (no tenant_id column)
            conn.execute(text("""
                INSERT INTO attacker_profiles (
                    attacker_id, source_ip, first_seen, last_seen, total_events, total_sessions,
                    highest_severity, attempted_usernames, attempted_commands, services_targeted, risk_score,
                    created_at, updated_at
                ) VALUES (
                    'atk-old-001', '198.51.100.99', '2026-11-17 12:00:00', '2026-11-17 12:05:00',
                    1, 1, 'low', '["admin"]', '["ls"]', '["ssh"]', 1.0,
                    '2026-11-17 12:00:00', '2026-11-17 12:00:00'
                )
            """))

            conn.execute(text("""
                INSERT INTO attacker_sessions (
                    session_id, attacker_id, source_ip, first_seen, last_seen,
                    services_accessed, event_count, status, created_at, updated_at
                ) VALUES (
                    'sess-old-001', 'atk-old-001', '198.51.100.99', '2026-11-17 12:00:00', '2026-11-17 12:05:00',
                    '["ssh"]', 1, 'active', '2026-11-17 12:00:00', '2026-11-17 12:00:00'
                )
            """))

            conn.execute(text("""
                INSERT INTO attack_events (
                    event_id, session_id, source_ip, source_port, source_service,
                    asset_id, event_type, username, severity, status, timestamp,
                    activity, metadata, created_at
                ) VALUES (
                    'evt-old-001', 'sess-old-001', '198.51.100.99', 54321, 'ssh',
                    'ssh-001', 'login_attempt', 'admin', 'low', 'failed', '2026-11-17 12:00:00',
                    '{}', '{}', '2026-11-17 12:00:00'
                )
            """))

        # 2. Upgrade to head (0002_multi_tenant_support)
        command.upgrade(alembic_cfg, "head")

        # 3. Verify schema and backfilled values
        with engine.connect() as conn:
            # Verify default tenant exists
            tenant_row = conn.execute(text("SELECT tenant_id, name, is_active FROM tenants WHERE tenant_id = 'tenant-apex-001'")).fetchone()
            assert tenant_row is not None
            assert tenant_row[0] == "tenant-apex-001"
            assert tenant_row[1] == "Apex Financial Group"

            # Verify attack_events backfill
            event_row = conn.execute(text("SELECT event_id, tenant_id FROM attack_events WHERE event_id = 'evt-old-001'")).fetchone()
            assert event_row is not None
            assert event_row[1] == "tenant-apex-001"

            # Verify attacker_sessions backfill
            sess_row = conn.execute(text("SELECT session_id, tenant_id FROM attacker_sessions WHERE session_id = 'sess-old-001'")).fetchone()
            assert sess_row is not None
            assert sess_row[1] == "tenant-apex-001"

            # Verify attacker_profiles backfill
            atk_row = conn.execute(text("SELECT attacker_id, tenant_id FROM attacker_profiles WHERE attacker_id = 'atk-old-001'")).fetchone()
            assert atk_row is not None
            assert atk_row[1] == "tenant-apex-001"

            # Verify deceptive_assets table and seeded default honeypots
            asset_rows = conn.execute(text("SELECT asset_id, tenant_id, status FROM deceptive_assets ORDER BY asset_id")).fetchall()
            assert len(asset_rows) >= 5
            asset_map = {row[0]: (row[1], row[2]) for row in asset_rows}
            assert "ssh-001" in asset_map
            assert asset_map["ssh-001"] == ("tenant-apex-001", "active")
            assert "ftp-001" in asset_map
            assert "web-001" in asset_map
            assert "db-001" in asset_map
            assert "canary-token-aws-01" in asset_map

            # Verify honeytokens table and seeded honeytokens from 0004 migration
            token_rows = conn.execute(text("SELECT token_id, tenant_id, asset_id, status FROM honeytokens ORDER BY token_id")).fetchall()
            assert len(token_rows) >= 2
            token_map = {row[0]: (row[1], row[2], row[3]) for row in token_rows}
            assert "htk-aws-prod-001" in token_map
            assert token_map["htk-aws-prod-001"] == ("tenant-apex-001", "canary-token-aws-01", "active")
            assert "htk-ssh-backup-001" in token_map
            assert token_map["htk-ssh-backup-001"] == ("tenant-apex-001", "ssh-001", "active")

            # Verify deployments table and seeded deployments from 0005 migration
            deploy_rows = conn.execute(text("SELECT deployment_id, tenant_id, asset_id, status FROM deployments ORDER BY deployment_id")).fetchall()
            assert len(deploy_rows) >= 5
            deploy_map = {row[0]: (row[1], row[2], row[3]) for row in deploy_rows}
            assert "deploy-ssh-prod-01" in deploy_map
            assert deploy_map["deploy-ssh-prod-01"] == ("tenant-apex-001", "ssh-001", "active")
            assert "deploy-ftp-prod-01" in deploy_map
            assert "deploy-web-prod-01" in deploy_map
            assert "deploy-db-prod-01" in deploy_map
            assert "deploy-token-aws-01" in deploy_map

            # Verify integration_configs table from 0006 migration
            intg_count = conn.execute(text("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='integration_configs'")).scalar()
            assert intg_count == 1

            # Verify webhook_deliveries table from 0007 migration
            webhook_count = conn.execute(text("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='webhook_deliveries'")).scalar()
            assert webhook_count == 1

        # 4. Downgrade back to 0001_initial_schema to verify clean reversal
        command.downgrade(alembic_cfg, "0001_initial_schema")

        # Verify tenants, deceptive_assets, honeytokens, deployments, integration_configs, and webhook_deliveries tables dropped
        with engine.connect() as conn:
            tenants_count = conn.execute(text("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='tenants'")).scalar()
            assert tenants_count == 0
            assets_count = conn.execute(text("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='deceptive_assets'")).scalar()
            assert assets_count == 0
            tokens_count = conn.execute(text("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='honeytokens'")).scalar()
            assert tokens_count == 0
            deployments_count = conn.execute(text("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='deployments'")).scalar()
            assert deployments_count == 0
            intg_dropped_count = conn.execute(text("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='integration_configs'")).scalar()
            assert intg_dropped_count == 0
            webhook_dropped_count = conn.execute(text("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='webhook_deliveries'")).scalar()
            assert webhook_dropped_count == 0

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
