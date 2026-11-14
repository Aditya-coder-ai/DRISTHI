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
    BASE_DIR: Path = BASE_DIR
    DECEPTION_ENV: str = get_env_str("DECEPTION_ENV", "development")
    LOG_LEVEL: str = get_env_str("LOG_LEVEL", "INFO")

    # SSH Deception Service (Cowrie)
    SSH_ASSET_ID: str = get_env_str("SSH_ASSET_ID", "ssh-001")
    SSH_HOSTNAME: str = get_env_str("SSH_HOSTNAME", "finance-server")
    SSH_LISTEN_HOST: str = get_env_str("SSH_LISTEN_HOST", "0.0.0.0")
    SSH_LISTEN_PORT: int = get_env_int("SSH_LISTEN_PORT", 2222)
    SSH_BASE_DIR: Path = BASE_DIR / "services" / "ssh"
    SSH_CONFIG_DIR: Path = SSH_BASE_DIR / "config"
    SSH_LOG_DIR: Path = BASE_DIR / "var" / "log" / "cowrie"
    SSH_JSON_LOG: Path = SSH_LOG_DIR / "cowrie.json"

    # FTP Deception Service (Phase 2)
    FTP_ASSET_ID: str = get_env_str("FTP_ASSET_ID", "ftp-001")
    FTP_SERVER_NAME: str = get_env_str("FTP_SERVER_NAME", "Corp-Storage-Node-02")
    FTP_LISTEN_HOST: str = get_env_str("FTP_LISTEN_HOST", "0.0.0.0")
    FTP_LISTEN_PORT: int = get_env_int("FTP_LISTEN_PORT", 2121)
    FTP_BASE_DIR: Path = BASE_DIR / "services" / "ftp"
    FTP_DECOY_DIR: Path = FTP_BASE_DIR / "decoy_root"
    FTP_CONFIG_FILE: Path = FTP_BASE_DIR / "config" / "ftp_config.json"
    FTP_LOG_DIR: Path = BASE_DIR / "var" / "log" / "ftp"
    FTP_JSON_LOG: Path = FTP_LOG_DIR / "ftp.json"

    # Web Admin Deception Service (Phase 3)
    WEB_ASSET_ID: str = get_env_str("WEB_ASSET_ID", "web-001")
    WEB_PORTAL_NAME: str = get_env_str("WEB_PORTAL_NAME", "Apex Internal Management System")
    WEB_LISTEN_HOST: str = get_env_str("WEB_LISTEN_HOST", "0.0.0.0")
    WEB_LISTEN_PORT: int = get_env_int("WEB_LISTEN_PORT", 8080)
    WEB_BASE_DIR: Path = BASE_DIR / "services" / "web"
    WEB_LOG_DIR: Path = BASE_DIR / "var" / "log" / "web"
    WEB_JSON_LOG: Path = WEB_LOG_DIR / "web.json"

    # Database Deception Service (Phase 4)
    DB_ASSET_ID: str = get_env_str("DB_ASSET_ID", "db-001")
    DB_SERVER_NAME: str = get_env_str("DB_SERVER_NAME", "db-cluster.corp.internal")
    DB_PG_LISTEN_HOST: str = get_env_str("DB_PG_LISTEN_HOST", "0.0.0.0")
    DB_PG_LISTEN_PORT: int = get_env_int("DB_PG_LISTEN_PORT", 5432)
    DB_MYSQL_LISTEN_HOST: str = get_env_str("DB_MYSQL_LISTEN_HOST", "0.0.0.0")
    DB_MYSQL_LISTEN_PORT: int = get_env_int("DB_MYSQL_LISTEN_PORT", 3306)
    DB_BASE_DIR: Path = BASE_DIR / "services" / "database"
    DB_LOG_DIR: Path = BASE_DIR / "var" / "log" / "database"
    DB_JSON_LOG: Path = DB_LOG_DIR / "database.json"

    # Dynamic Bait Credentials & Canaries (Phase 5)
    CREDENTIALS_FILE: Path = BASE_DIR / "credentials" / "decoy_credentials.json"
    CREDENTIALS_DIR: Path = BASE_DIR / "services" / "credentials"
    CREDENTIALS_AUDIT_LOG: Path = BASE_DIR / "var" / "log" / "credentials" / "audit.json"

    # Central Event Collection & Forwarding Daemon (Phase 6)
    DAEMON_FLUSH_INTERVAL: float = float(get_env_str("DAEMON_FLUSH_INTERVAL", "2.0"))
    DAEMON_PID_FILE: Path = BASE_DIR / "var" / "run" / "collector_daemon.pid"

    # Backend Integration (Person 2)
    BACKEND_API_URL: str = get_env_str("BACKEND_API_URL", "http://localhost:8000/api/events")
    BACKEND_API_KEY: Optional[str] = os.environ.get("BACKEND_API_KEY")
    EVENT_BATCH_SIZE: int = get_env_int("EVENT_BATCH_SIZE", 50)
    RETRY_LIMIT: int = get_env_int("RETRY_LIMIT", 5)


settings = Settings()

