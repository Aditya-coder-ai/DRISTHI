"""SQLAlchemy Declarative Base for DRISTHI Central Database."""

import os
os.environ.setdefault("DISABLE_SQLALCHEMY_CEXT", "1")

from datetime import datetime, timezone
from sqlalchemy import Column, DateTime
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Base model class with automatic UTC timestamps."""
    pass
