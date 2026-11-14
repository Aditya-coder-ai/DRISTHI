"""Central Backend Configuration Settings for DRISTHI."""

import os
from pathlib import Path
from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


# Root directory of the backend module
BACKEND_DIR = Path(__file__).resolve().parent.parent.parent
PROJECT_ROOT = BACKEND_DIR.parent


class BackendSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="allow")

    PROJECT_NAME: str = "DRISTHI Central Backend & Threat Telemetry"
    VERSION: str = "1.0.0"
    API_V1_PREFIX: str = "/api"
    DEBUG: bool = False

    # Database: Default to local SQLite file if PostgreSQL is not specified
    # Format for PostgreSQL: postgresql+psycopg://postgres:postgres@localhost:5432/drishti
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        f"sqlite:///{PROJECT_ROOT / 'var' / 'data' / 'drishti_central.db'}"
    )

    # Authentication Secret for Ingestion (Shared with Person 1's collector)
    BACKEND_API_KEY: Optional[str] = os.getenv("BACKEND_API_KEY", "")

    # Allowed CORS Origins for Dashboard UI
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
        "http://localhost:8080",
    ]

    # Session Lifecycle Thresholds
    SESSION_IDLE_TIMEOUT_SECONDS: int = 1800  # 30 mins idle -> session closed
    MAX_BATCH_INGESTION_SIZE: int = 200



settings = BackendSettings()
