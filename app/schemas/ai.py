"""
Purpose: Pydantic schemas for AI Security Assistant endpoints.

Responsibilities:
- Define request and response models for /api/ai/analyze, /api/ai/fix, /api/ai/report, and /api/ai/chat.

Dependencies:
- pydantic.BaseModel, Field
- typing.Optional, List, Dict, Any

Usage:
    from app.schemas.ai import AnalyzeRequest, FixRequest, ChatRequest
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    """Request model for POST /api/ai/analyze."""

    title: str = Field(..., json_schema_extra={"example": "Hardcoded AWS Secret Key"})
    severity: str = Field(..., json_schema_extra={"example": "CRITICAL"})
    file: str = Field(..., json_schema_extra={"example": "config/aws.py"})
    line: Optional[int] = Field(default=None, json_schema_extra={"example": 14})
    rule_id: str = Field(default="aws-access-key", json_schema_extra={"example": "aws-access-key"})
    code_snippet: Optional[str] = Field(default=None, json_schema_extra={"example": "AWS_SECRET_KEY = 'sk_test_12345'"})


class FixRequest(BaseModel):
    """Request model for POST /api/ai/fix."""

    vulnerable_code: str = Field(..., json_schema_extra={"example": "eval(user_input)"})
    language: str = Field(default="python", json_schema_extra={"example": "python"})
    rule_id: Optional[str] = Field(default="python-eval", json_schema_extra={"example": "python-eval"})


class ReportRequest(BaseModel):
    """Request model for POST /api/ai/report."""

    repository: str = Field(..., json_schema_extra={"example": "octocat/Hello-World"})
    total_scans: int = Field(default=1, json_schema_extra={"example": 5})
    critical_count: int = Field(default=0, json_schema_extra={"example": 1})
    high_count: int = Field(default=0, json_schema_extra={"example": 2})
    medium_count: int = Field(default=0, json_schema_extra={"example": 3})
    low_count: int = Field(default=0, json_schema_extra={"example": 1})


class ChatRequest(BaseModel):
    """Request model for POST /api/ai/chat."""

    message: str = Field(..., json_schema_extra={"example": "What is CWE-79 and how to fix it?"})
    context: Optional[str] = Field(default=None, json_schema_extra={"example": "Context from scan finding..."})
