"""
Purpose: SQLAlchemy declarative base model.

Responsibilities:
- Declarative Base class for all ORM models.

Dependencies:
- sqlalchemy.orm.DeclarativeBase

Usage:
    from app.db.base import Base
"""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Declarative Base class for SQLAlchemy ORM models."""
    pass
