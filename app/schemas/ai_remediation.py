"""
Purpose: Pydantic schemas for AI Secure Code Remediation Engine.

Responsibilities:
- Define request and response models for POST /api/ai/fix matching exact user specification.

Dependencies:
- pydantic.BaseModel, Field
- typing.List, Optional

Usage:
    from app.schemas.ai_remediation import RemediationResponse
"""

from typing import List, Optional
from pydantic import BaseModel, Field


class RemediationRequest(BaseModel):
    """Request model for POST /api/ai/fix."""

    vulnerable_code: str = Field(..., json_schema_extra={"example": "password = 'admin123'"})
    language: Optional[str] = Field(default=None, json_schema_extra={"example": "python"})
    rule_id: Optional[str] = Field(default="hardcoded-password", json_schema_extra={"example": "hardcoded-password"})
    filename: Optional[str] = Field(default="vulnerable.py", json_schema_extra={"example": "vulnerable.py"})
    severity: Optional[str] = Field(default="HIGH", json_schema_extra={"example": "HIGH"})


class RemediationResponse(BaseModel):
    """Structured AI Secure Code Remediation Response."""

    language: str = Field(..., json_schema_extra={"example": "python"})
    vulnerability: str = Field(..., json_schema_extra={"example": "Hardcoded Password / Credential Exposure"})
    severity: str = Field(..., json_schema_extra={"example": "HIGH"})
    confidence: float = Field(..., json_schema_extra={"example": 0.96})
    summary: str = Field(..., json_schema_extra={"example": "Replaced hardcoded password with dynamic environment variable lookup."})
    reasoning: str = Field(..., json_schema_extra={"example": "Hardcoding credentials exposes sensitive secrets in git logs. Environment variables keep secrets out of source code."})
    original_code: str = Field(..., json_schema_extra={"example": "password = 'admin123'"})
    secure_code: str = Field(..., json_schema_extra={"example": "password = os.getenv('APP_PASSWORD')"})
    diff: str = Field(..., json_schema_extra={"example": "- password = 'admin123'\n+ password = os.getenv('APP_PASSWORD')"})
    patch: str = Field(..., json_schema_extra={"example": "--- a/vulnerable.py\n+++ b/vulnerable.py\n@@ -1 +1 @@\n- password = 'admin123'\n+ password = os.getenv('APP_PASSWORD')"})
    breaking_change: bool = Field(..., json_schema_extra={"example": False})
    manual_review_required: bool = Field(..., json_schema_extra={"example": False})
    recommendation: str = Field(..., json_schema_extra={"example": "Store secrets in environment variables or GitHub Secrets."})
    references: List[str] = Field(default_factory=list, json_schema_extra={"example": ["https://cwe.mitre.org/data/definitions/798.html"]})
