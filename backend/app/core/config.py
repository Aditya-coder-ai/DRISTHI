"""Central Backend Configuration Settings for DRISTHI."""

import os
from pathlib import Path
from typing import Any, List, Optional, Union
from pydantic import field_validator
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

    # Multi-Tenant Isolation
    DEFAULT_TENANT_ID: str = os.getenv("DEFAULT_TENANT_ID", os.getenv("TENANT_ID", "tenant-apex-001"))

    # Allowed CORS Origins for Dashboard UI
    FRONTEND_ORIGINS: Optional[str] = os.getenv("FRONTEND_ORIGINS", None)
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
        "http://localhost:8080",
    ]

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Any) -> List[str]:
        default_origins = [
            "http://localhost:3000",
            "http://localhost:5173",
            "http://127.0.0.1:3000",
            "http://127.0.0.1:5173",
            "http://localhost:8080",
        ]
        origins_to_check = os.getenv("FRONTEND_ORIGINS") or os.getenv("CORS_ORIGINS")
        if origins_to_check:
            if origins_to_check.strip().startswith("["):
                import json
                try:
                    return json.loads(origins_to_check)
                except Exception:
                    pass
            parsed = [i.strip() for i in origins_to_check.split(",") if i.strip()]
            if parsed:
                # Merge with default development origins, preserving uniqueness
                return list(dict.fromkeys(default_origins + parsed))
        if isinstance(v, list):
            return v
        return default_origins

    # Session Lifecycle Thresholds
    SESSION_IDLE_TIMEOUT_SECONDS: int = 1800  # 30 mins idle -> session closed
    MAX_BATCH_INGESTION_SIZE: int = 200

    # Webhook Delivery & Verification Settings
    WEBHOOK_TIMEOUT_SECONDS: int = int(os.getenv("WEBHOOK_TIMEOUT_SECONDS", "5"))
    WEBHOOK_MAX_RETRIES: int = int(os.getenv("WEBHOOK_MAX_RETRIES", "3"))
    WEBHOOK_ALLOW_INTERNAL_URLS: bool = os.getenv("WEBHOOK_ALLOW_INTERNAL_URLS", "false").lower() in ("true", "1", "yes")
    STRIPE_WEBHOOK_SECRET: Optional[str] = None
    STRIPE_WEBHOOK_TOLERANCE_SECONDS: int = int(os.getenv("STRIPE_WEBHOOK_TOLERANCE_SECONDS", "300"))



settings = BackendSettings()
