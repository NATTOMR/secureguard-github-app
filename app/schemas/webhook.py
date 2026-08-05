"""
Purpose: Schemas for GitHub webhook payloads and responses.

Responsibilities:
- Define request and response structures for GitHub webhook events.
- Provide a structured parsed event model for push and pull_request dispatch.

Dependencies:
- pydantic.BaseModel

Usage:
    from app.schemas.webhook import WebhookAckResponse, WebhookEventPayload
"""

from typing import Literal, Optional
from pydantic import BaseModel, Field


class WebhookAckResponse(BaseModel):
    """Response schema for webhook acknowledgment."""

    status: str = Field(..., json_schema_extra={"example": "received"})
    event: Optional[str] = Field(default=None, json_schema_extra={"example": "push"})
    delivery_id: Optional[str] = Field(default=None, json_schema_extra={"example": "12345-67890"})


class WebhookEventPayload(BaseModel):
    """Structured payload extracted from a GitHub webhook event for pipeline dispatch."""

    event_type: Literal["push", "pull_request"]
    owner: str = Field(..., description="Repository owner login")
    repo: str = Field(..., description="Repository name")
    commit_sha: str = Field(..., description="Target commit SHA to scan")
    installation_id: Optional[int] = Field(default=None, description="GitHub App installation ID")
    pr_number: Optional[int] = Field(default=None, description="Pull request number (PR events only)")
    ref: Optional[str] = Field(default=None, description="Git ref (push events only, e.g. refs/heads/main)")

