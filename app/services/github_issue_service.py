"""
Purpose: Service for creating formatted GitHub Issues when security findings are detected.

Responsibilities:
- Format security findings into structured markdown issues matching required schema.
- Communicate with GitHub REST API using Installation Access Token.

Dependencies:
- httpx
- typing.List, Dict, Any
- app.models.finding.FindingModel
- app.core.logging.get_logger
- app.core.exceptions.GitHubAPIError

Usage:
    issue_service = GitHubIssueService()
    issue_data = await issue_service.create_security_issue(
        owner="octocat",
        repo="Hello-World",
        scan_report=scan_report_dict,
        token="ghs_12345..."
    )
"""

from typing import Any, Dict, List, Optional
import httpx

from app.core.exceptions import GitHubAPIError
from app.core.logging import get_logger

logger = get_logger(__name__)


class GitHubIssueService:
    """Service to create formatted GitHub Issues for security findings."""

    GITHUB_API_URL = "https://api.github.com"

    def format_issue_body(self, scan_report: Dict[str, Any]) -> str:
        """Format scan report dictionary into the required Markdown issue structure."""
        critical = scan_report.get("critical", 0)
        high = scan_report.get("high", 0)
        medium = scan_report.get("medium", 0)
        low = scan_report.get("low", 0)
        findings = scan_report.get("findings", [])

        lines = []
        lines.append("# SecureGuard Security Report\n")
        lines.append("## Summary\n")
        lines.append(f"Critical: {critical}")
        lines.append(f"High: {high}")
        lines.append(f"Medium: {medium}")
        lines.append(f"Low: {low}\n")
        lines.append("## Findings\n")

        for f in findings:
            lines.append(f"**Severity:** {f.get('severity', 'UNKNOWN')}")
            lines.append(f"**File:** `{f.get('file', 'unknown')}`")
            lines.append(f"**Line:** {f.get('line') or 'N/A'}")
            lines.append(f"**Rule:** {f.get('rule', 'unknown')}")
            lines.append(f"**Description:** {f.get('description', 'N/A')}\n")

        lines.append("---\n*Reported automatically by SecureGuard GitHub App.*")
        return "\n".join(lines)

    async def create_security_issue(
        self,
        owner: str,
        repo: str,
        scan_report: Dict[str, Any],
        token: str,
    ) -> Dict[str, Any]:
        """Create a security issue on the target GitHub repository."""
        title = f"🚨 [SecureGuard] Security Findings Detected in {owner}/{repo}"
        body = self.format_issue_body(scan_report)

        url = f"{self.GITHUB_API_URL}/repos/{owner}/{repo}/issues"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        payload = {
            "title": title,
            "body": body,
            "labels": ["secureguard", "security"],
        }

        logger.info("Creating security issue on %s/%s", owner, repo)
        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=headers, json=payload, timeout=30.0)
            if response.status_code not in (200, 201):
                logger.error("Failed to create GitHub issue: %s", response.text)
                raise GitHubAPIError(
                    f"Failed to create GitHub Issue: {response.text}",
                    status_code=response.status_code,
                )
            logger.info("Successfully created GitHub issue on %s/%s", owner, repo)
            return response.json()
