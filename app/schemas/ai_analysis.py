"""
Purpose: Pydantic response schema for AI Vulnerability Analysis Engine.

Responsibilities:
- Enforce strict JSON contract matching user specification for /api/ai/analyze.

Dependencies:
- pydantic.BaseModel, Field
- typing.List, Optional

Usage:
    from app.schemas.ai_analysis import AIAnalysisResponse
"""

from typing import List, Optional
from pydantic import BaseModel, Field


class AIAnalysisResponse(BaseModel):
    """Structured AI Vulnerability Analysis Response."""

    title: str = Field(..., json_schema_extra={"example": "Hardcoded AWS Secret Key"})
    summary: str = Field(..., json_schema_extra={"example": "Plaintext secret detected in repository configuration."})
    technical_explanation: str = Field(..., json_schema_extra={"example": "Credentials hardcoded in code expose authentication tokens."})
    attack_scenario: str = Field(..., json_schema_extra={"example": "Attacker scans repository, extracts key, and accesses AWS services."})
    business_impact: str = Field(..., json_schema_extra={"example": "Financial loss, cloud resource hijacking, regulatory non-compliance."})
    risk_level: str = Field(..., json_schema_extra={"example": "CRITICAL"})
    confidence: str = Field(..., json_schema_extra={"example": "HIGH"})
    cvss_estimate: float = Field(..., json_schema_extra={"example": 9.8})
    cwe: str = Field(..., json_schema_extra={"example": "CWE-798: Use of Hard-coded Credentials"})
    owasp: str = Field(..., json_schema_extra={"example": "A07:2021-Identification and Authentication Failures"})
    mitre_attack: str = Field(..., json_schema_extra={"example": "T1552.001: Unsecured Credentials - Credentials In Files"})
    recommendation: str = Field(..., json_schema_extra={"example": "Revoke exposed secret and load credentials via environment variables."})
    secure_example: str = Field(..., json_schema_extra={"example": "api_key = os.getenv('AWS_SECRET_KEY')"})
    references: List[str] = Field(default_factory=list, json_schema_extra={"example": ["https://cwe.mitre.org/data/definitions/798.html"]})
