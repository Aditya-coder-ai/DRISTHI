"""Configuration management for the Deception Platform."""

import os
from pathlib import Path
from typing import Optional


# Project Root Directory
BASE_DIR = Path(__file__).resolve().parent.parent


def get_env_str(key: str, default: str) -> str:
    return os.environ.get(key, default)


def get_env_int(key: str, default: int) -> int:
    val = os.environ.get(key)
    if val is not None:
        try:
            return int(val)
        except ValueError:
            pass
    return default


def get_env_bool(key: str, default: bool) -> bool:
    val = os.environ.get(key)
    if val is not None:
        return val.strip().lower() in ("true", "1", "yes", "on")
    return default


class Settings:
    # General
    DECEPTION_ENV: str = get_env_str("DECEPTION_ENV", "development")
    LOG_LEVEL: str = get_env_str("LOG_LEVEL", "INFO")

    # SSH Deception Service (Cowrie)
    SSH_ASSET_ID: str = get_env_str("SSH_ASSET_ID", "ssh-001")
    SSH_HOSTNAME: str = get_env_str("SSH_HOSTNAME", "finance-server")
    SSH_LISTEN_HOST: str = get_env_str("SSH_LISTEN_HOST", "0.0.0.0")
    SSH_LISTEN_PORT: int = get_env_int("SSH_LISTEN_PORT", 2222)
    SSH_BASE_DIR: Path = BASE_DIR / "services" / "ssh"
    SSH_CONFIG_DIR: Path = SSH_BASE_DIR / "config"
    SSH_LOG_DIR: Path = SSH_BASE_DIR / "var" / "log" / "cowrie"
    SSH_JSON_LOG: Path = SSH_LOG_DIR / "cowrie.json"

    # Backend Integration (Person 2)
    BACKEND_API_URL: str = get_env_str("BACKEND_API_URL", "http://localhost:8000/api/events")
    BACKEND_API_KEY: Optional[str] = os.environ.get("BACKEND_API_KEY")
    EVENT_BATCH_SIZE: int = get_env_int("EVENT_BATCH_SIZE", 50)
    RETRY_LIMIT: int = get_env_int("RETRY_LIMIT", 5)


settings = Settings()
