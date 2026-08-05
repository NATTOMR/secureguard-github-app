"""
Purpose: Pydantic schemas for SOC Integration APIs.

Responsibilities:
- Define request/response schemas for /api/integrations/* routes.

Dependencies:
- pydantic.BaseModel, Field
- typing.Dict, Any, Optional

Usage:
    from app.schemas.integrations import DispatchAlertRequest
"""

from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class DispatchAlertRequest(BaseModel):
    """Request payload to dispatch alert to SOC platforms."""

    title: str = Field(..., json_schema_extra={"example": "Hardcoded AWS Access Key"})
    severity: str = Field(..., json_schema_extra={"example": "CRITICAL"})
    repository: str = Field(..., json_schema_extra={"example": "octocat/Hello-World"})
    scanner: str = Field(default="Gitleaks", json_schema_extra={"example": "Gitleaks"})
    rule_id: str = Field(default="aws-access-key", json_schema_extra={"example": "aws-access-key"})
    file: str = Field(..., json_schema_extra={"example": "config/aws.py"})
    line: Optional[int] = Field(default=14, json_schema_extra={"example": 14})
    ai_summary: Optional[str] = Field(default="Plaintext AWS credential leak.", json_schema_extra={"example": "Plaintext AWS credential leak."})
