"""
Purpose: SQLAlchemy 2.0 ORM models for SecureGuard Web Dashboard.

Responsibilities:
- Map Repositories, Scans, Findings, and Events database tables.
- Define foreign key relationships and index structures for query optimization.

Dependencies:
- datetime
- uuid
- sqlalchemy.Column, Integer, String, Float, DateTime, ForeignKey, Index
- sqlalchemy.orm.relationship
- app.db.base.Base

Usage:
    from app.db.models import RepositoryModel, ScanModel, FindingModel, EventModel
"""

from datetime import datetime, timezone
import uuid
from typing import List, Optional

from sqlalchemy import Column, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class RepositoryModel(Base):
    """Repository database table model."""

    __tablename__ = "repositories"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    owner: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    default_branch: Mapped[str] = mapped_column(String(100), default="main")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    scans: Mapped[List["ScanModel"]] = relationship("ScanModel", back_populates="repository", cascade="all, delete-orphan")
    events: Mapped[List["EventModel"]] = relationship("EventModel", back_populates="repository", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_repo_owner_name", "owner", "name", unique=True),
    )


class ScanModel(Base):
    """Scan execution history table model."""

    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    repository_id: Mapped[int] = mapped_column(Integer, ForeignKey("repositories.id"), nullable=False, index=True)
    commit_sha: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    branch: Mapped[str] = mapped_column(String(100), default="main")
    trigger: Mapped[str] = mapped_column(String(50), default="push")  # push, pull_request, manual
    status: Mapped[str] = mapped_column(String(50), default="completed")  # queued, in_progress, completed, failed
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    duration: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Relationships
    repository: Mapped["RepositoryModel"] = relationship("RepositoryModel", back_populates="scans")
    findings: Mapped[List["FindingModel"]] = relationship("FindingModel", back_populates="scan", cascade="all, delete-orphan")


class FindingModel(Base):
    """Security finding database table model."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=False, index=True)
    scanner: Mapped[str] = mapped_column(String(50), nullable=False, index=True)  # Gitleaks, Semgrep
    severity: Mapped[str] = mapped_column(String(20), nullable=False, index=True)  # CRITICAL, HIGH, MEDIUM, LOW
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    file: Mapped[str] = mapped_column(String(500), nullable=False, index=True)
    line: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    rule: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    recommendation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    cwe: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    owasp: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    cvss: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="open", index=True)  # open, resolved, ignored

    # Relationships
    scan: Mapped["ScanModel"] = relationship("ScanModel", back_populates="findings")


class EventModel(Base):
    """Webhook delivery audit log table model."""

    __tablename__ = "events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    repository_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("repositories.id"), nullable=True, index=True)
    event: Mapped[str] = mapped_column(String(50), nullable=False, index=True)  # push, pull_request
    delivery_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    repository: Mapped[Optional["RepositoryModel"]] = relationship("RepositoryModel", back_populates="events")


class AIAnalysisModel(Base):
    """AI Analysis audit database table model."""

    __tablename__ = "ai_analyses"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    finding_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    latency: Mapped[float] = mapped_column(Float, default=0.0)
    tokens_used: Mapped[int] = mapped_column(Integer, default=0)
    analysis_json: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
