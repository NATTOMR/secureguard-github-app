"""
Purpose: Service to create GitHub Issues for critical/high severity findings.

Responsibilities:
- Open an issue per finding (or group them) with clear title and details.
- Deduplicate: avoid creating duplicate issues by checking existing open issues with a `secureguard` label.
- Use Installation Access Token for authentication.

Dependencies:
- httpx async client
- app.auth.github_auth.GitHubAuthManager for token retrieval
- app.core.logging.get_logger

Usage:
    await IssueService().create_issues(owner, repo, findings, token)
"""

import json
from typing import List, Dict, Any

import httpx

from app.core.logging import get_logger

logger = get_logger(__name__)


class IssueService:
    """Handles GitHub Issue creation for high severity findings."""

    GITHUB_API_URL = "https://api.github.com"
    ISSUE_LABEL = "secureguard"

    async def _list_open_issues(self, owner: str, repo: str, token: str) -> List[Dict[str, Any]]:
        url = f"{self.GITHUB_API_URL}/repos/{owner}/{repo}/issues"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers, params={"state": "open", "labels": self.ISSUE_LABEL}, timeout=30.0)
            response.raise_for_status()
            return response.json()

    def _issue_exists(self, open_issues: List[Dict[str, Any]], title: str) -> bool:
        return any(issue.get("title") == title for issue in open_issues)

    async def create_issues(self, owner: str, repo: str, findings: List[Dict[str, Any]], token: str) -> List[Dict[str, Any]]:
        """Create GitHub Issues for each critical/high finding.

        Returns a list of created issue responses.
        """
        open_issues = await self._list_open_issues(owner, repo, token)
        created = []
        for f in findings:
            title = f"[SecureGuard] {f['severity']} - {f['title']} in {f['file_path']}"
            if self._issue_exists(open_issues, title):
                logger.info("Issue already exists, skipping: %s", title)
                continue
            body = (
                f"**Severity:** {f['severity']}\n"
                f"**File:** `{f['file_path']}`:{f.get('line_number') or 'N/A'}\n"
                f"**Description:** {f.get('description') or 'N/A'}\n"
                f"**Recommendation:** {f.get('recommendation') or 'N/A'}\n"
            )
            payload = {
                "title": title,
                "body": body,
                "labels": [self.ISSUE_LABEL],
            }
            url = f"{self.GITHUB_API_URL}/repos/{owner}/{repo}/issues"
            headers = {
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            }
            async with httpx.AsyncClient() as client:
                logger.info("Creating GitHub issue: %s", title)
                response = await client.post(url, headers=headers, json=payload, timeout=30.0)
                response.raise_for_status()
                created.append(response.json())
        return created
