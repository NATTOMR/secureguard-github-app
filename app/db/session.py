"""
Purpose: Database connection factory and session management.

Responsibilities:
- Create engine supporting SQLite / PostgreSQL.
- Expose session generator for FastAPI dependency injection.
- Provide init_db helper to create tables automatically.

Dependencies:
- sqlalchemy.create_engine
- sqlalchemy.orm.sessionmaker, Session
- app.core.config.get_settings

Usage:
    from app.db.session import get_db, init_db
"""

from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from app.core.config import get_settings
from app.db.base import Base

settings = get_settings()

db_url = settings.DATABASE_URL
connect_args = {"check_same_thread": False} if db_url.startswith("sqlite") else {}

engine = create_engine(
    db_url,
    connect_args=connect_args,
    pool_pre_ping=True,
    echo=False,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db() -> None:
    """Create database tables if they do not exist."""
    from app.db import models  # noqa: F401
    Base.metadata.create_all(bind=engine)


def get_db() -> Generator[Session, None, None]:
    """Dependency provider for SQLAlchemy Session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
