"""
Purpose: Pydantic schemas for authentication API endpoints.

Responsibilities:
- Define response models for `/auth/status` and `/auth/test` endpoints.

Dependencies:
- pydantic.BaseModel

Usage:
    from app.schemas.auth import AuthStatusResponse, AuthTestResponse
"""

from typing import Optional
from pydantic import BaseModel, Field


class AuthStatusResponse(BaseModel):
    """Response schema for GET /auth/status."""

    authenticated: bool = Field(..., json_schema_extra={"example": True})
    app_id: Optional[str] = Field(default=None, json_schema_extra={"example": "4492546"})
    installation_id: Optional[str] = Field(default=None, json_schema_extra={"example": "123456"})
    environment: str = Field(..., json_schema_extra={"example": "development"})


class AuthTestResponse(BaseModel):
    """Response schema for GET /auth/test."""

    status: str = Field(..., json_schema_extra={"example": "success"})
    message: str = Field(..., json_schema_extra={"example": "GitHub App authenticated successfully."})
    app_name: Optional[str] = Field(default=None, json_schema_extra={"example": "SecureGuard"})
