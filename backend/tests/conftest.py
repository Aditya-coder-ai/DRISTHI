"""Global Pytest Fixtures for DRISTHI Central Backend."""

import os
from datetime import datetime, timezone
os.environ.setdefault("DISABLE_SQLALCHEMY_CEXT", "1")

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.core.config import settings
from backend.app.database.base import Base
from backend.app.database.connection import get_db
from backend.app.main import app
import backend.app.models  # ensure models registered


@pytest.fixture(scope="function")
def test_db():
    """Provides an isolated in-memory SQLite database session for each test."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(test_db):
    """Provides a FastAPI TestClient bound to the isolated in-memory test database."""
    def override_get_db():
        try:
            yield test_db
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def sample_ssh_event():
    return {
        "event_id": "evt-ssh-001",
        "asset_id": "ssh-001",
        "event_type": "command_execution",
        "source_ip": "198.51.100.25",
        "source_port": 52140,
        "username": "finance_admin",
        "protocol": "SSH",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "status": "executed",
        "metadata": {
            "command": "cat /etc/passwd",
            "session_id": "cowrie-sess-1001",
            "hostname": "finance-server",
        },
    }


@pytest.fixture
def sample_ftp_event():
    return {
        "event_id": "evt-ftp-001",
        "asset_id": "ftp-001",
        "event_type": "file_download",
        "source_ip": "198.51.100.25",
        "source_port": 52142,
        "username": "backup_user",
        "protocol": "FTP",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "status": "success",
        "metadata": {
            "path": "/backups/finance/customer_database.sql",
            "filename": "customer_database.sql",
            "bytes_transferred": 8192,
            "session_id": "ftp-sess-2002",
        },
    }


@pytest.fixture
def sample_canary_event():
    return {
        "event_id": "evt-canary-001",
        "asset_id": "db-001",
        "event_type": "canary_triggered",
        "source_ip": "198.51.100.25",
        "source_port": 52144,
        "username": "database_root",
        "protocol": "DATABASE",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "status": "detected",
        "metadata": {
            "canary_triggered": True,
            "alert_priority": "HIGH",
            "target_asset": "db-001",
        },
    }

