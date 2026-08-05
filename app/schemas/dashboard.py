"""
Purpose: Pydantic response schemas for Dashboard REST APIs.

Responsibilities:
- Define strongly typed response models for /api/dashboard, /api/repositories, /api/scans, /api/findings, /api/events.

Dependencies:
- pydantic.BaseModel
- typing.List, Optional, Dict, Any

Usage:
    from app.schemas.dashboard import DashboardOverviewResponse
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class FindingResponse(BaseModel):
    """Schema for individual finding in API responses."""

    id: str
    scan_id: str
    scanner: str
    severity: str
    title: str
    description: Optional[str] = None
    file: str
    line: Optional[int] = None
    rule: str
    recommendation: Optional[str] = None
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    cvss: Optional[float] = None
    status: str


class ScanDetailResponse(BaseModel):
    """Schema for scan summary and detailed findings."""

    id: str
    repository_id: int
    repository_name: str
    commit_sha: str
    branch: str
    trigger: str
    status: str
    started_at: datetime
    finished_at: Optional[datetime] = None
    duration: Optional[float] = None
    total_findings: int
    findings: List[FindingResponse] = []


class RepositoryResponse(BaseModel):
    """Schema for repository summary in API responses."""

    id: int
    owner: str
    name: str
    full_name: str
    default_branch: str
    created_at: datetime
    risk_score: float
    total_scans: int
    open_findings: int


class EventResponse(BaseModel):
    """Schema for audit event response."""

    id: str
    repository_id: Optional[int] = None
    event: str
    delivery_id: Optional[str] = None
    created_at: datetime


class DashboardOverviewResponse(BaseModel):
    """Schema for GET /api/dashboard overview metrics."""

    total_repositories: int
    total_scans: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    secrets_count: int
    sast_count: int
    latest_scans: List[Dict[str, Any]]
    recent_events: List[Dict[str, Any]]
