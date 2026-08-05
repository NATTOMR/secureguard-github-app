"""
Purpose: Reusable GitHub REST API client wrapper.

Responsibilities:
- Provide unified client interface for GitHub API requests.
- Expose helper functions: `get_authenticated_app`, `get_installation`, `get_installation_token`, `get_repository`, `request`.

Dependencies:
- httpx.AsyncClient
- app.auth.github_auth.GitHubAuthManager
- app.github.app_client.GitHubAppClient
- app.github.repository_client.GitHubRepositoryClient
- app.core.exceptions.GitHubAPIError

Usage:
    client = GitHubClient(auth_manager)
    app_data = await client.get_authenticated_app()
    repo_data = await client.get_repository("owner", "repo")
"""

from typing import Any, Dict, Optional
import httpx
from app.auth.github_auth import GitHubAuthManager
from app.core.exceptions import GitHubAPIError
from app.github.app_client import GitHubAppClient
from app.github.repository_client import GitHubRepositoryClient


class GitHubClient:
    """Unified client wrapper for GitHub REST API operations."""

    def __init__(self, auth_manager: GitHubAuthManager, base_url: str = "https://api.github.com") -> None:
        self.auth_manager = auth_manager
        self.base_url = base_url.rstrip("/")
        self.app_client = GitHubAppClient(auth_manager, base_url)
        self.repo_client = GitHubRepositoryClient(auth_manager, base_url)

    async def get_authenticated_app(self) -> Dict[str, Any]:
        """Get metadata for the authenticated GitHub App."""
        return await self.app_client.get_authenticated_app()

    async def get_installation(self, installation_id: int) -> Dict[str, Any]:
        """Get installation details for a given installation ID."""
        return await self.app_client.get_installation(installation_id)

    async def get_installation_token(self, installation_id: Optional[int] = None) -> str:
        """Get or refresh installation access token."""
        return await self.auth_manager.get_installation_token(installation_id)

    async def get_repository(self, owner: str, repo: str, installation_id: Optional[int] = None) -> Dict[str, Any]:
        """Get repository metadata."""
        return await self.repo_client.get_repository(owner, repo, installation_id)

    async def request(
        self,
        method: str,
        endpoint: str,
        token: Optional[str] = None,
        use_jwt: bool = False,
        json_payload: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Generic HTTP request helper for GitHub REST API endpoints."""
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        
        if use_jwt:
            auth_token = self.auth_manager.get_app_jwt()
        elif token:
            auth_token = token
        else:
            auth_token = await self.auth_manager.get_installation_token()

        headers = {
            "Authorization": f"Bearer {auth_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        async with httpx.AsyncClient() as client:
            response = await client.request(
                method,
                url,
                headers=headers,
                json=json_payload,
                params=params,
                timeout=10.0,
            )

            if response.status_code >= 400:
                raise GitHubAPIError(
                    f"GitHub API {method} {endpoint} returned status {response.status_code}: {response.text}",
                    status_code=response.status_code,
                )

            return response.json()
