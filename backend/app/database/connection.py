"""Database engine and session management for DRISTHI Central Backend."""

from pathlib import Path
from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from backend.app.core.config import settings
from backend.app.core.logging import logger
from backend.app.database.base import Base


def get_engine():
    db_url = settings.DATABASE_URL
    connect_args = {}

    if db_url.startswith("sqlite"):
        # Ensure parent directory exists for SQLite db file
        if "///" in db_url and not db_url.startswith("sqlite:///:memory:"):
            db_path = Path(db_url.split("///")[-1])
            db_path.parent.mkdir(parents=True, exist_ok=True)
        connect_args["check_same_thread"] = False
        engine = create_engine(db_url, connect_args=connect_args)
    else:
        # PostgreSQL pool configuration
        engine = create_engine(
            db_url,
            pool_size=10,
            max_overflow=20,
            pool_pre_ping=True,
        )
    return engine


engine = get_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that provides a transactional database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create all database tables if they do not exist."""
    logger.info("Initializing database schema on %s...", settings.DATABASE_URL.split("@")[-1])
    # Import all models so Base has registered them
    import backend.app.models.tenant
    import backend.app.models.asset
    import backend.app.models.event
    import backend.app.models.session
    import backend.app.models.attacker
    import backend.app.models.mitre

    Base.metadata.create_all(bind=engine)
    logger.info("Database schema initialized successfully.")

