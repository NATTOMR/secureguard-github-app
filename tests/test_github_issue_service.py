"""
Purpose: Unit tests for GitHubIssueService formatting and creation.

Responsibilities:
- Verify issue markdown formatting matching required layout.
- Verify GitHub REST API issue creation HTTP request.

Dependencies:
- pytest
- unittest.mock
- app.services.github_issue_service.GitHubIssueService

Usage:
    pytest tests/test_github_issue_service.py -v
"""

from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from app.services.github_issue_service import GitHubIssueService


def test_issue_formatting():
    """Test format_issue_body produces required structure."""
    service = GitHubIssueService()
    report = {
        "status": "success",
        "critical": 1,
        "high": 2,
        "medium": 0,
        "low": 0,
        "findings": [
            {
                "severity": "CRITICAL",
                "file": "config.py",
                "line": 15,
                "rule": "aws-access-key",
                "description": "AWS Key leaked",
            }
        ],
    }

    body = service.format_issue_body(report)

    assert "# SecureGuard Security Report" in body
    assert "Critical: 1" in body
    assert "High: 2" in body
    assert "**Severity:** CRITICAL" in body
    assert "**File:** `config.py`" in body
    assert "**Line:** 15" in body


@pytest.mark.asyncio
async def test_create_security_issue_http_call():
    """Test create_security_issue performs POST request."""
    service = GitHubIssueService()
    report = {
        "status": "success",
        "critical": 1,
        "high": 0,
        "medium": 0,
        "low": 0,
        "findings": [],
    }

    mock_res = MagicMock()
    mock_res.status_code = 201
    mock_res.json.return_value = {"id": 1, "number": 42}

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_res
        res = await service.create_security_issue("owner", "repo", report, "mock_token")

        assert res["number"] == 42
        assert mock_post.called
