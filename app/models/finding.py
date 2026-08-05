"""
Purpose: Finding domain model representing security vulnerabilities and leaked secrets.

Responsibilities:
- Strongly typed representation of individual security findings.
- Field definitions required by SecureGuard scanning pipeline.

Dependencies:
- pydantic.BaseModel
- typing.Optional

Usage:
    finding = FindingModel(
        id="finding-1",
        title="Leaked AWS Access Key",
        description="Found potential AWS Access Key ID",
        severity="HIGH",
        file="config/aws.py",
        line=14,
        rule="aws-access-key",
        secret_type="AWS Access Key",
        commit="7fd1a60b01f91b314f59955a4e4d4e80d8edf11d",
        author="developer@example.com"
    )
"""

from typing import Optional
from pydantic import BaseModel, Field


class FindingModel(BaseModel):
    """Domain model representing a detected security finding or secret leak."""

    id: str = Field(..., description="Unique finding identifier")
    title: str = Field(..., description="Short summary title of the finding")
    description: str = Field(..., description="Detailed description of the finding")
    severity: str = Field(..., description="Severity level: CRITICAL, HIGH, MEDIUM, or LOW")
    file: str = Field(..., description="Relative file path where finding was detected")
    line: Optional[int] = Field(default=None, description="Line number of finding in file")
    rule: str = Field(..., description="Rule ID that triggered this finding")
    secret_type: str = Field(..., description="Categorized secret type or vulnerability class")
    commit: Optional[str] = Field(default=None, description="Commit SHA associated with finding")
    author: Optional[str] = Field(default=None, description="Author email or username of commit")
