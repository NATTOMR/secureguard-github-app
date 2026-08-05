"""
Purpose: Service for building Markdown reports and managing GitHub PR review comments.

Responsibilities:
- Format scan results into structured Pull Request markdown reports.
- Support clean scan messages when zero findings are detected.
- Post new PR review comments or update existing SecureGuard comments to avoid duplicates.

Dependencies:
- httpx
- typing.List, Dict, Any, Optional
- app.models.scan_result.ScanResult, Finding
- app.core.logging.get_logger
- app.core.exceptions.GitHubAPIError

Usage:
    review_service = PRReviewService()
    report_md = review_service.generate_pr_markdown_report(scan_result)
    result = await review_service.post_or_update_pr_comment(
        owner="octocat",
        repo="Hello-World",
        pr_number=42,
        markdown_body=report_md,
        token="ghs_12345..."
    )
"""

from typing import Any, Dict, List, Optional
import httpx

from app.core.exceptions import GitHubAPIError
from app.core.logging import get_logger
from app.models.scan_result import ScanResult

logger = get_logger(__name__)


class PRReviewService:
    """Service to format and post/update Pull Request review comments on GitHub."""

    GITHUB_API_URL = "https://api.github.com"
    COMMENT_MARKER = "SecureGuard"

    def generate_pr_markdown_report(self, scan_result: ScanResult) -> str:
        """Format ScanResult domain model into PR Markdown review layout."""
        if scan_result.total_findings == 0:
            return (
                "# ✅ SecureGuard\n\n"
                "No security issues detected.\n\n"
                "Great work."
            )

        critical_count = scan_result.critical_findings
        high_count = scan_result.high_findings
        
        # Calculate medium and low counts
        medium_count = sum(1 for f in scan_result.findings if f.severity.upper() == "MEDIUM")
        low_count = sum(1 for f in scan_result.findings if f.severity.upper() in ("LOW", "INFO"))

        lines: List[str] = []
        lines.append("# 🛡 SecureGuard Security Review\n")
        lines.append("## Summary\n")
        lines.append("| Severity | Count |")
        lines.append("|----------|------:|")
        lines.append(f"| Critical | {critical_count} |")
        lines.append(f"| High | {high_count} |")
        lines.append(f"| Medium | {medium_count} |")
        lines.append(f"| Low | {low_count} |\n")
        lines.append("---\n")
        lines.append("## Findings\n")

        # Group findings by severity (Critical -> High -> Medium -> Low)
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        emoji_map = {
            "CRITICAL": "🚨",
            "HIGH": "🔴",
            "MEDIUM": "🟡",
            "LOW": "🔵",
            "INFO": "ℹ️",
        }

        grouped_findings = sorted(
            scan_result.findings,
            key=lambda f: severity_order.index(f.severity.upper()) if f.severity.upper() in severity_order else 99
        )

        for finding in grouped_findings:
            sev_upper = finding.severity.upper()
            emoji = emoji_map.get(sev_upper, "⚠️")
            formatted_sev = sev_upper.capitalize()

            lines.append(f"### {emoji} {formatted_sev}\n")
            lines.append(f"**{finding.title}**\n")
            lines.append("File:")
            lines.append(f"{finding.file_path}\n")
            lines.append("Line:")
            lines.append(f"{finding.line_number or 'N/A'}\n")
            
            recommendation = finding.recommendation or finding.description or "Review and fix potential security vulnerability."
            lines.append("Recommendation:\n")
            lines.append(f"{recommendation}\n")
            lines.append("---\n")

        return "\n".join(lines)

    async def post_or_update_pr_comment(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        markdown_body: str,
        token: str,
    ) -> Dict[str, Any]:
        """Post a new PR comment or update existing SecureGuard comment."""
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        async with httpx.AsyncClient() as client:
            # 1. Search existing issue/PR comments for SecureGuard marker
            existing_comment_id = await self._find_existing_comment(
                client, owner, repo, pr_number, headers
            )

            if existing_comment_id:
                # 2. Update existing comment (PATCH)
                logger.info("Updating existing SecureGuard comment #%s on PR #%d", existing_comment_id, pr_number)
                url = f"{self.GITHUB_API_URL}/repos/{owner}/{repo}/issues/comments/{existing_comment_id}"
                res = await client.patch(url, headers=headers, json={"body": markdown_body}, timeout=30.0)
                if res.status_code not in (200, 201):
                    logger.error("Failed to update PR comment #%s: %s", existing_comment_id, res.text)
                    raise GitHubAPIError(f"Failed to update PR comment: {res.text}", status_code=res.status_code)
                return res.json()

            # 3. Post new PR comment (POST)
            logger.info("Posting new SecureGuard review comment on PR #%d", pr_number)
            url = f"{self.GITHUB_API_URL}/repos/{owner}/{repo}/issues/{pr_number}/comments"
            res = await client.post(url, headers=headers, json={"body": markdown_body}, timeout=30.0)
            if res.status_code not in (200, 201):
                logger.error("Failed to post PR comment on PR #%d: %s", pr_number, res.text)
                raise GitHubAPIError(f"Failed to post PR comment: {res.text}", status_code=res.status_code)
            return res.json()

    async def _find_existing_comment(
        self,
        client: httpx.AsyncClient,
        owner: str,
        repo: str,
        pr_number: int,
        headers: Dict[str, str],
    ) -> Optional[int]:
        """Find ID of previous comment created by SecureGuard on the given PR."""
        url = f"{self.GITHUB_API_URL}/repos/{owner}/{repo}/issues/{pr_number}/comments"
        try:
            res = await client.get(url, headers=headers, timeout=30.0)
            if res.status_code == 200:
                comments = res.json()
                for c in comments:
                    body = c.get("body", "")
                    if self.COMMENT_MARKER in body:
                        return c.get("id")
        except Exception as e:
            logger.warning("Error searching for existing PR comments: %s", str(e))
        return None
