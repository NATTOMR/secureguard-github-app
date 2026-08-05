"""
Purpose: GitHub Repository client endpoints.

Responsibilities:
- Provide API functions to query repository details using installation tokens.

Dependencies:
- httpx.AsyncClient
- app.auth.github_auth.GitHubAuthManager
- app.core.exceptions.GitHubAPIError

Usage:
    repo_client = GitHubRepositoryClient(auth_manager)
    repo_info = await repo_client.get_repository("octocat", "Hello-World")
"""

from typing import Any, Dict, Optional
import httpx
from app.auth.github_auth import GitHubAuthManager
from app.core.exceptions import GitHubAPIError


class GitHubRepositoryClient:
    """Specialized client for Repository operations using Installation tokens."""

    def __init__(self, auth_manager: GitHubAuthManager, base_url: str = "https://api.github.com") -> None:
        self.auth_manager = auth_manager
        self.base_url = base_url.rstrip("/")

    async def get_repository(
        self, owner: str, repo: str, installation_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """Fetch metadata for a target repository (GET /repos/{owner}/{repo})."""
        token = await self.auth_manager.get_installation_token(installation_id)
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        async with httpx.AsyncClient() as client:
            url = f"{self.base_url}/repos/{owner}/{repo}"
            response = await client.get(url, headers=headers, timeout=10.0)

            if response.status_code != 200:
                raise GitHubAPIError(
                    f"Failed to fetch repository {owner}/{repo}: {response.text}",
                    status_code=response.status_code,
                )

            return response.json()
