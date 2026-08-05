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
    """Create database tables and auto-migrate missing columns for SQLite."""
    from app.db import models  # noqa: F401
    Base.metadata.create_all(bind=engine)

    if db_url.startswith("sqlite"):
        from sqlalchemy import inspect, text
        inspector = inspect(engine)
        if "repositories" in inspector.get_table_names():
            columns = {col["name"] for col in inspector.get_columns("repositories")}
            with engine.connect() as conn:
                alter_statements = []
                if "github_repository_id" not in columns:
                    alter_statements.append("ALTER TABLE repositories ADD COLUMN github_repository_id INTEGER")
                if "full_name" not in columns:
                    alter_statements.append("ALTER TABLE repositories ADD COLUMN full_name VARCHAR(255)")
                if "private" not in columns:
                    alter_statements.append("ALTER TABLE repositories ADD COLUMN private BOOLEAN DEFAULT 0")
                if "visibility" not in columns:
                    alter_statements.append("ALTER TABLE repositories ADD COLUMN visibility VARCHAR(50) DEFAULT 'public'")
                if "language" not in columns:
                    alter_statements.append("ALTER TABLE repositories ADD COLUMN language VARCHAR(100)")
                if "size" not in columns:
                    alter_statements.append("ALTER TABLE repositories ADD COLUMN size INTEGER DEFAULT 0")
                if "archived" not in columns:
                    alter_statements.append("ALTER TABLE repositories ADD COLUMN archived BOOLEAN DEFAULT 0")
                if "disabled" not in columns:
                    alter_statements.append("ALTER TABLE repositories ADD COLUMN disabled BOOLEAN DEFAULT 0")
                if "is_active" not in columns:
                    alter_statements.append("ALTER TABLE repositories ADD COLUMN is_active BOOLEAN DEFAULT 1")
                if "html_url" not in columns:
                    alter_statements.append("ALTER TABLE repositories ADD COLUMN html_url VARCHAR(500)")
                if "last_push" not in columns:
                    alter_statements.append("ALTER TABLE repositories ADD COLUMN last_push DATETIME")
                if "last_sync" not in columns:
                    alter_statements.append("ALTER TABLE repositories ADD COLUMN last_sync DATETIME")
                if "updated_at" not in columns:
                    alter_statements.append("ALTER TABLE repositories ADD COLUMN updated_at DATETIME")
                
                for stmt in alter_statements:
                    try:
                        conn.execute(text(stmt))
                    except Exception:
                        pass
                conn.commit()


def get_db() -> Generator[Session, None, None]:
    """Dependency provider for SQLAlchemy Session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
