"""
Purpose: Automated tests for Phase 3 GitHub Issue Automation APIs (/api/github/issues*).
"""

from unittest.mock import AsyncMock, patch
import pytest


def test_list_github_issues_endpoint(client):
    """Test GET /api/github/issues endpoint."""
    res = client.get("/api/github/issues")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)


def test_get_github_issue_not_found(client):
    """Test GET /api/github/issues/{id} 404 response."""
    res = client.get("/api/github/issues/non-existent-id")
    assert res.status_code == 404


@pytest.mark.asyncio
async def test_create_github_issue_flow(client):
    """Test POST /api/github/issues/create endpoint validation."""
    # Attempting with non-existent finding should return 404
    payload = {
        "finding_id": "invalid-finding-uuid",
        "owner": "NATTOMR",
        "repo": "secureguard-github-app"
    }
    res = client.post("/api/github/issues/create", json=payload)
    assert res.status_code == 404
