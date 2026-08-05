"""
Purpose: GitHub App identity client endpoints.

Responsibilities:
- Provide API functions to query GitHub App identity and installation metadata.

Dependencies:
- httpx.AsyncClient
- app.auth.github_auth.GitHubAuthManager
- app.core.exceptions.GitHubAPIError

Usage:
    app_client = GitHubAppClient(auth_manager)
    app_info = await app_client.get_authenticated_app()
"""

from typing import Any, Dict, Optional
import httpx
from app.auth.github_auth import GitHubAuthManager
from app.core.exceptions import GitHubAPIError


class GitHubAppClient:
    """Specialized client for GitHub App-authenticated API operations."""

    def __init__(self, auth_manager: GitHubAuthManager, base_url: str = "https://api.github.com") -> None:
        self.auth_manager = auth_manager
        self.base_url = base_url.rstrip("/")

    async def get_authenticated_app(self) -> Dict[str, Any]:
        """Fetch metadata for the authenticated GitHub App (GET /app)."""
        jwt_token = self.auth_manager.get_app_jwt()
        headers = {
            "Authorization": f"Bearer {jwt_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        async with httpx.AsyncClient() as client:
            response = await client.get(f"{self.base_url}/app", headers=headers, timeout=10.0)

            if response.status_code != 200:
                raise GitHubAPIError(
                    f"Failed to fetch authenticated app info: {response.text}",
                    status_code=response.status_code,
                )

            return response.json()

    async def get_installation(self, installation_id: int) -> Dict[str, Any]:
        """Fetch details for a specific GitHub App installation (GET /app/installations/{id})."""
        jwt_token = self.auth_manager.get_app_jwt()
        headers = {
            "Authorization": f"Bearer {jwt_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        async with httpx.AsyncClient() as client:
            url = f"{self.base_url}/app/installations/{installation_id}"
            response = await client.get(url, headers=headers, timeout=10.0)

            if response.status_code != 200:
                raise GitHubAPIError(
                    f"Failed to fetch installation {installation_id}: {response.text}",
                    status_code=response.status_code,
                )

            return response.json()
