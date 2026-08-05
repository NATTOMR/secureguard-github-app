"""
Purpose: Schemas for scan API endpoints.

Responsibilities:
- Define request and response structures for `/scan` endpoints.

Dependencies:
- pydantic.BaseModel
- typing.List, Optional
- datetime.datetime

Usage:
    from app.schemas.scan import ScanRequest, ScanResponse
"""

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    """Request schema for initiating a repository scan."""

    owner: str = Field(..., json_schema_extra={"example": "NATTOMR"})
    repo: str = Field(..., json_schema_extra={"example": "secureguard-github-app"})
    commit_sha: str = Field(..., json_schema_extra={"example": "main"})
    installation_id: Optional[int] = Field(default=None, json_schema_extra={"example": 151376506})
    pr_number: Optional[int] = Field(default=None, json_schema_extra={"example": None})
    notify_github: bool = Field(default=False, description="Whether to post comments/issues to GitHub after scanning")


class FindingSchema(BaseModel):
    """Schema for a single security finding."""

    rule_id: str
    title: str
    severity: str
    file_path: str
    line_number: Optional[int] = None
    description: Optional[str] = None
    recommendation: Optional[str] = None
    scanner_name: Optional[str] = None


class ScanResponse(BaseModel):
    """Response schema for a completed scan."""

    scan_id: str
    repository: str
    commit_sha: str
    timestamp: datetime
    total_findings: int
    has_critical_or_high: bool
    github_comment_posted: bool = False
    github_issues_created: int = 0
    findings: List[FindingSchema]
