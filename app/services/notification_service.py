"""
Purpose: Orchestrates GitHub notification actions after a scan finishes.

Responsibilities:
- Obtain installation token using GitHubAuthManager.
- Generate Markdown report via ReportService.
- Post PR or Commit comment via CommentService.
- Create GitHub issues for Critical/High findings via IssueService.

Dependencies:
- app.auth.github_auth.GitHubAuthManager
- app.models.scan_result.ScanResult
- app.services.report_service.ReportService
- app.github.comment_service.CommentService
- app.github.issue_service.IssueService
- app.core.logging.get_logger

Usage:
    notification_service = GitHubNotificationService(auth_manager, report_service, comment_service, issue_service)
    status = await notification_service.notify(scan_result, owner, repo, pr_number, installation_id)
"""

from typing import Dict, Any, Optional

from app.auth.github_auth import GitHubAuthManager
from app.core.logging import get_logger
from app.github.comment_service import CommentService
from app.github.issue_service import IssueService
from app.models.scan_result import ScanResult
from app.services.report_service import ReportService

logger = get_logger(__name__)


class GitHubNotificationService:
    """Orchestrates report generation, PR/Commit commenting, and Issue creation."""

    def __init__(
        self,
        auth_manager: GitHubAuthManager,
        report_service: Optional[ReportService] = None,
        comment_service: Optional[CommentService] = None,
        issue_service: Optional[IssueService] = None,
    ) -> None:
        self.auth_manager = auth_manager
        self.report_service = report_service or ReportService()
        self.comment_service = comment_service or CommentService()
        self.issue_service = issue_service or IssueService()

    async def notify(
        self,
        scan_result: ScanResult,
        owner: str,
        repo: str,
        pr_number: Optional[int] = None,
        installation_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Process scan result and dispatch notifications to GitHub."""
        summary = {
            "github_comment_posted": False,
            "github_issues_created": 0,
        }

        try:
            token = await self.auth_manager.get_installation_token(installation_id)
        except Exception as e:
            logger.warning("Failed to obtain installation token for notifications: %s", str(e))
            return summary

        # 1. Generate Markdown Report & Post Comment
        report_md = self.report_service.generate(scan_result)
        try:
            if pr_number:
                await self.comment_service.post_pr_comment(owner, repo, pr_number, report_md, token)
            else:
                await self.comment_service.post_commit_comment(owner, repo, scan_result.commit_sha, report_md, token)
            summary["github_comment_posted"] = True
        except Exception as e:
            logger.error("Failed to post comment to GitHub: %s", str(e))

        # 2. Create Issues for Critical and High findings
        high_critical_findings = [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "description": f.description,
                "recommendation": f.recommendation,
                "scanner_name": f.scanner_name,
            }
            for f in scan_result.findings
            if f.severity.upper() in ("CRITICAL", "HIGH")
        ]

        if high_critical_findings:
            try:
                created = await self.issue_service.create_issues(owner, repo, high_critical_findings, token)
                summary["github_issues_created"] = len(created)
            except Exception as e:
                logger.error("Failed to create GitHub issues: %s", str(e))

        return summary
