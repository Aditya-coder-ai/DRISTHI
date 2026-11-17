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

        # 4. Downgrade back to 0001_initial_schema to verify clean reversal
        command.downgrade(alembic_cfg, "0001_initial_schema")

        # Verify tenants table dropped and tenant_id column removed
        with engine.connect() as conn:
            result = conn.execute(text("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='tenants'")).scalar()
            assert result == 0

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
