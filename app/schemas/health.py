"""
Purpose: Schemas for root and health check endpoint responses.

Responsibilities:
- Define data structures for root endpoint (`/`) and health check (`/health`).

Dependencies:
- pydantic.BaseModel

Usage:
    from app.schemas.health import HealthResponse, RootResponse
"""

from typing import Dict
from pydantic import BaseModel, Field


class RootResponse(BaseModel):
    """Schema for the root endpoint response."""

    name: str = Field(..., json_schema_extra={"example": "SecureGuard"})
    version: str = Field(..., json_schema_extra={"example": "0.1.0"})
    status: str = Field(..., json_schema_extra={"example": "operational"})
    docs_url: str = Field(..., json_schema_extra={"example": "/docs"})


class HealthResponse(BaseModel):
    """Schema for the health check endpoint response."""

    status: str = Field(..., json_schema_extra={"example": "healthy"})
    app_name: str = Field(..., json_schema_extra={"example": "SecureGuard"})
    version: str = Field(..., json_schema_extra={"example": "0.1.0"})
    environment: str = Field(..., json_schema_extra={"example": "production"})
    checks: Dict[str, str] = Field(
        default_factory=dict,
        json_schema_extra={"example": {"database": "ok", "github_api": "ok"}}
    )
