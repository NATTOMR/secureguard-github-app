"""
Purpose: Service to post scan results back to GitHub as comments.

Responsibilities:
- Post a markdown security report as a PR review comment (if a PR number is provided).
- Fallback to a commit comment when scanning a push event (no PR).
- Use the GitHub Installation Access Token for authentication.

Dependencies:
- httpx (async HTTP client)
- app.auth.github_auth.GitHubAuthManager for token retrieval
- app.core.logging.get_logger

Usage:
    await CommentService().post_pr_comment(owner, repo, pr_number, body, token)
    await CommentService().post_commit_comment(owner, repo, commit_sha, body, token)
"""

import json
from typing import Any

import httpx

from app.core.logging import get_logger

logger = get_logger(__name__)


class CommentService:
    """Handles posting comments to GitHub Pull Requests and commits."""

    GITHUB_API_URL = "https://api.github.com"

    async def post_pr_comment(self, owner: str, repo: str, pr_number: int, body: str, token: str) -> Any:
        """Create a PR review comment with the provided markdown body.

        Returns the GitHub API response JSON.
        """
        url = f"{self.GITHUB_API_URL}/repos/{owner}/{repo}/pulls/{pr_number}/reviews"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        payload = {
            "event": "COMMENT",
            "body": body,
        }
        async with httpx.AsyncClient() as client:
            logger.info("Posting PR comment to %s", url)
            response = await client.post(url, headers=headers, json=payload, timeout=30.0)
            response.raise_for_status()
            return response.json()

    async def post_commit_comment(self, owner: str, repo: str, commit_sha: str, body: str, token: str) -> Any:
        """Create a comment tied to a specific commit SHA."""
        url = f"{self.GITHUB_API_URL}/repos/{owner}/{repo}/commits/{commit_sha}/comments"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        payload = {"body": body}
        async with httpx.AsyncClient() as client:
            logger.info("Posting commit comment to %s", url)
            response = await client.post(url, headers=headers, json=payload, timeout=30.0)
            response.raise_for_status()
            return response.json()
