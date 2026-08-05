"""
Purpose: Pydantic schemas for SARIF and report export endpoints.

Responsibilities:
- Define response models for /api/export/sarif, /api/export/pdf, /api/export/html.

Dependencies:
- pydantic.BaseModel

Usage:
    from app.schemas.export import ExportMetadata
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ExportMetadata(BaseModel):
    """Metadata included in every exported report."""

    scan_id: str
    repository: str
    commit_sha: str
    branch: str
    generated_at: datetime
    format: str  # sarif, pdf, html
    total_findings: int


class SARIFRule(BaseModel):
    """Schema for a SARIF rule definition within a tool driver."""

    id: str
    name: str
    shortDescription: Dict[str, str]
    fullDescription: Optional[Dict[str, str]] = None
    defaultConfiguration: Dict[str, str]
    helpUri: Optional[str] = None
    properties: Optional[Dict[str, Any]] = None


class SARIFResult(BaseModel):
    """Schema for a single SARIF result entry."""

    ruleId: str
    ruleIndex: int
    level: str  # error, warning, note
    message: Dict[str, str]
    locations: List[Dict[str, Any]]
    fingerprints: Optional[Dict[str, str]] = None
    properties: Optional[Dict[str, Any]] = None
