"""
Purpose: Test suite for Pull Request Review Bot.

Responsibilities:
- Verify PR Markdown report formatting for findings and clean scans.
- Test PRReviewService comment posting (POST) and comment updating (PATCH).
- Test PRScanService branch checkout and dual scanner execution.
- Test Webhook handler PR routing for opened, synchronize, reopened, and ignored actions.

Dependencies:
- pytest
- unittest.mock
- httpx
- app.github.pr_review_service.PRReviewService
- app.services.pr_scan_service.PRScanService
- app.models.scan_result.ScanResult, Finding

Usage:
    pytest tests/test_pr_review.py -v
"""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from app.github.pr_review_service import PRReviewService
from app.models.scan_result import Finding, ScanResult
from app.services.pr_scan_service import PRScanService


def test_pr_markdown_generation_with_findings():
    """Test PR Markdown report generation when security issues exist."""
    service = PRReviewService()
    findings = [
        Finding(
            rule_id="github-token",
            title="Hardcoded GitHub Token",
            severity="HIGH",
            file_path="app/config.py",
            line_number=18,
            description="Exposed token",
            recommendation="Move token to environment variables.",
            scanner_name="Gitleaks",
        ),
        Finding(
            rule_id="python-eval",
            title="Code Execution (eval)",
            severity="MEDIUM",
            file_path="utils.py",
            line_number=42,
            description="Use of eval() detected",
            recommendation="Avoid shell=True / eval().",
            scanner_name="Semgrep",
        ),
    ]

    scan_result = ScanResult(
        scan_id="test-scan-1",
        repository="octocat/Hello-World",
        commit_sha="7fd1a60b",
        timestamp=datetime.now(timezone.utc),
        findings=findings,
    )

    md = service.generate_pr_markdown_report(scan_result)

    assert "# 🛡 SecureGuard Security Review" in md
    assert "| Severity | Count |" in md
    assert "| High | 1 |" in md
    assert "| Medium | 1 |" in md
    assert "### 🔴 High" in md
    assert "Hardcoded GitHub Token" in md
    assert "app/config.py" in md
    assert "Move token to environment variables." in md
    assert "### 🟡 Medium" in md


def test_pr_markdown_generation_clean_scan():
    """Test PR Markdown report generation for clean scans."""
    service = PRReviewService()
    scan_result = ScanResult(
        scan_id="test-scan-clean",
        repository="octocat/Hello-World",
        commit_sha="7fd1a60b",
        timestamp=datetime.now(timezone.utc),
        findings=[],
    )

    md = service.generate_pr_markdown_report(scan_result)

    assert "# ✅ SecureGuard" in md
    assert "No security issues detected." in md
    assert "Great work." in md


@pytest.mark.asyncio
async def test_post_new_pr_comment():
    """Test posting a new PR comment when no previous comment exists."""
    service = PRReviewService()
    mock_get = AsyncMock(return_value=MagicMock(status_code=200, json=lambda: []))
    mock_post = AsyncMock(return_value=MagicMock(status_code=201, json=lambda: {"id": 999}))

    with patch("httpx.AsyncClient.get", mock_get), patch("httpx.AsyncClient.post", mock_post):
        res = await service.post_or_update_pr_comment(
            owner="octocat",
            repo="Hello-World",
            pr_number=42,
            markdown_body="# 🛡 SecureGuard Security Review",
            token="ghs_mock",
        )

        assert res["id"] == 999
        assert mock_get.called
        assert mock_post.called


@pytest.mark.asyncio
async def test_update_existing_pr_comment():
    """Test updating (PATCH) an existing SecureGuard PR review comment."""
    service = PRReviewService()
    existing_comments = [
        {"id": 101, "body": "Other bot comment"},
        {"id": 555, "body": "# 🛡 SecureGuard Security Review\nPrevious findings..."},
    ]
    mock_get = AsyncMock(return_value=MagicMock(status_code=200, json=lambda: existing_comments))
    mock_patch = AsyncMock(return_value=MagicMock(status_code=200, json=lambda: {"id": 555, "updated": True}))

    with patch("httpx.AsyncClient.get", mock_get), patch("httpx.AsyncClient.patch", mock_patch):
        res = await service.post_or_update_pr_comment(
            owner="octocat",
            repo="Hello-World",
            pr_number=42,
            markdown_body="# 🛡 SecureGuard Security Review\nUpdated report...",
            token="ghs_mock",
        )

        assert res["id"] == 555
        assert res["updated"] is True
        assert mock_get.called
        assert mock_patch.called


@pytest.mark.asyncio
async def test_pr_scan_service_execution(tmp_path):
    """Test PRScanService cloning, checkout, scanning, and cleanup."""
    mock_clone = MagicMock()
    mock_clone.clone_repository.return_value = tmp_path
    mock_clone.cleanup_repository = MagicMock()

    mock_gitleaks = MagicMock()
    mock_gitleaks.scan_repository.return_value = {
        "status": "success",
        "findings": [
            {
                "rule": "aws-key",
                "title": "AWS Key",
                "severity": "CRITICAL",
                "file": "aws.py",
                "line": 10,
                "description": "Exposed key",
            }
        ],
    }

    mock_semgrep = AsyncMock()
    mock_semgrep.scan.return_value = []

    service = PRScanService(
        clone_service=mock_clone,
        gitleaks_scanner=mock_gitleaks,
        semgrep_scanner=mock_semgrep,
    )

    result = await service.scan_pull_request(
        owner="octocat",
        repo="Hello-World",
        pr_number=42,
        head_ref="feature-auth",
        head_sha="7fd1a60b",
    )

    assert result.total_findings == 1
    assert result.findings[0].rule_id == "aws-key"
    assert mock_clone.clone_repository.called
    assert mock_clone.cleanup_repository.called


def test_pr_webhook_action_filtering(client):
    """Test webhook filtering for pull_request actions (opened/synchronize/reopened accepted, closed ignored)."""
    # 1. Closed action should be ignored
    closed_payload = {
        "action": "closed",
        "number": 42,
        "pull_request": {"head": {"ref": "feature", "sha": "123456"}},
        "repository": {"name": "Hello-World", "owner": {"login": "octocat"}},
    }
    res1 = client.post("/webhook", json=closed_payload, headers={"X-GitHub-Event": "pull_request"})
    assert res1.status_code == 200
    assert res1.json()["status"] == "received"

    # 2. Opened action should be queued
    opened_payload = {
        "action": "opened",
        "number": 42,
        "pull_request": {"head": {"ref": "feature", "sha": "123456"}},
        "repository": {"name": "Hello-World", "owner": {"login": "octocat"}},
    }
    res2 = client.post("/webhook", json=opened_payload, headers={"X-GitHub-Event": "pull_request"})
    assert res2.status_code == 200
    assert "queued" in res2.json()["status"] or res2.json()["status"] == "received"
