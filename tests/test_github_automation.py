"""
Purpose: Automated tests for GitHub automation services (comments, issues, notifications).

Responsibilities:
- Verify CommentService PR and Commit comment HTTP calls.
- Verify IssueService creation and deduplication logic.
- Verify GitHubNotificationService orchestration flow.

Dependencies:
- pytest
- unittest.mock
- app.github.comment_service.CommentService
- app.github.issue_service.IssueService
- app.services.notification_service.GitHubNotificationService
- app.models.scan_result.ScanResult, Finding

Usage:
    pytest tests/test_github_automation.py -v
"""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from app.github.comment_service import CommentService
from app.github.issue_service import IssueService
from app.models.scan_result import Finding, ScanResult
from app.services.notification_service import GitHubNotificationService


@pytest.mark.asyncio
async def test_comment_service_post_pr_comment():
    """Test post_pr_comment makes correct HTTP POST request."""
    comment_service = CommentService()
    
    mock_response = MagicMock()
    mock_response.json.return_value = {"id": 101, "body": "Scan Report"}
    mock_response.raise_for_status = MagicMock()

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_response
        res = await comment_service.post_pr_comment("owner", "repo", 42, "# Report", "mock-token")
        
        assert res["id"] == 101
        assert mock_post.called
        args, kwargs = mock_post.call_args
        assert "pulls/42/reviews" in args[0]
        assert kwargs["headers"]["Authorization"] == "Bearer mock-token"


@pytest.mark.asyncio
async def test_issue_service_create_issues_with_deduplication():
    """Test IssueService creates issues and skips existing ones."""
    issue_service = IssueService()
    
    # Mock open issues response (one existing issue)
    mock_get_res = MagicMock()
    mock_get_res.json.return_value = [
        {"title": "[SecureGuard] CRITICAL - Leaked AWS Key in config.py"}
    ]
    mock_get_res.raise_for_status = MagicMock()

    # Mock post response for new issue creation
    mock_post_res = MagicMock()
    mock_post_res.json.return_value = {"number": 1, "title": "[SecureGuard] HIGH - SQLi in db.py"}
    mock_post_res.raise_for_status = MagicMock()

    findings = [
        {
            "title": "Leaked AWS Key",
            "severity": "CRITICAL",
            "file_path": "config.py",
            "line_number": 12,
            "description": "AWS Key leaked",
            "recommendation": "Rotate key",
        },
        {
            "title": "SQLi in db.py",
            "severity": "HIGH",
            "file_path": "db.py",
            "line_number": 55,
            "description": "SQL injection vulnerability",
            "recommendation": "Use parameterized queries",
        },
    ]

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get, \
         patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_get.return_value = mock_get_res
        mock_post.return_value = mock_post_res
        
        created = await issue_service.create_issues("owner", "repo", findings, "mock-token")
        
        # Only 1 issue should be created because the first one was duplicate
        assert len(created) == 1
        assert created[0]["title"] == "[SecureGuard] HIGH - SQLi in db.py"


@pytest.mark.asyncio
async def test_notification_service_orchestration():
    """Test full GitHubNotificationService orchestration."""
    mock_auth = MagicMock()
    mock_auth.get_installation_token = AsyncMock(return_value="mock-token")

    mock_report = MagicMock()
    mock_report.generate.return_value = "# Report Markdown"

    mock_comment = MagicMock()
    mock_comment.post_pr_comment = AsyncMock(return_value={"id": 1})

    mock_issue = MagicMock()
    mock_issue.create_issues = AsyncMock(return_value=[{"number": 10}])

    scan_result = ScanResult(
        scan_id="scan-999",
        repository="owner/repo",
        commit_sha="123456",
        timestamp=datetime.now(timezone.utc),
        findings=[
            Finding(
                rule_id="r1",
                title="Critical Secret",
                severity="CRITICAL",
                file_path="main.py",
                line_number=1,
            )
        ],
    )

    notifier = GitHubNotificationService(
        auth_manager=mock_auth,
        report_service=mock_report,
        comment_service=mock_comment,
        issue_service=mock_issue,
    )

    summary = await notifier.notify(scan_result, "owner", "repo", pr_number=5, installation_id=123)

    assert summary["github_comment_posted"] is True
    assert summary["github_issues_created"] == 1
    mock_comment.post_pr_comment.assert_called_once_with("owner", "repo", 5, "# Report Markdown", "mock-token")
    mock_issue.create_issues.assert_called_once()
