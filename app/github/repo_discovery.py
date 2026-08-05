"""
Purpose: Service for discovering all repositories installed for the GitHub App.

Responsibilities:
- Call GitHub REST API `GET /installation/repositories` using Installation Access Tokens.
- Handle pagination (`page`, `per_page`) to discover all accessible repositories.
- Extract and normalize fields: id, name, full_name, private, default_branch, html_url, clone_url, language, size, archived, disabled, visibility, pushed_at, updated_at.

Dependencies:
- httpx.AsyncClient
- app.auth.github_auth.GitHubAuthManager
- app.core.exceptions.GitHubAPIError
- app.core.logging.get_logger
"""

from typing import Any, Dict, List, Optional
import httpx

from app.auth.github_auth import GitHubAuthManager
from app.core.exceptions import GitHubAPIError
from app.core.logging import get_logger

logger = get_logger(__name__)


class GitHubRepoDiscoveryService:
    """Service to discover installed GitHub App repositories via REST API."""

    def __init__(self, auth_manager: GitHubAuthManager, base_url: str = "https://api.github.com") -> None:
        self.auth_manager = auth_manager
        self.base_url = base_url.rstrip("/")

    async def list_installation_repositories(
        self, installation_id: Optional[int] = None, per_page: int = 100
    ) -> List[Dict[str, Any]]:
        """Fetch all repositories accessible to the GitHub App installation with pagination."""
        token = await self.auth_manager.get_installation_token(installation_id)
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        all_repos: List[Dict[str, Any]] = []
        page = 1

        async with httpx.AsyncClient() as client:
            while True:
                url = f"{self.base_url}/installation/repositories?per_page={per_page}&page={page}"
                logger.info("Fetching installation repositories page %d from %s", page, url)
                response = await client.get(url, headers=headers, timeout=15.0)

                if response.status_code != 200:
                    logger.error("Failed to fetch installation repositories: HTTP %d %s", response.status_code, response.text)
                    raise GitHubAPIError(
                        f"Failed to fetch installation repositories: {response.text}",
                        status_code=response.status_code,
                    )

                data = response.json()
                raw_repos = data.get("repositories", [])
                if not raw_repos:
                    break

                for repo_data in raw_repos:
                    owner_obj = repo_data.get("owner", {})
                    owner_name = owner_obj.get("login") if isinstance(owner_obj, dict) else ""
                    
                    parsed = {
                        "github_repository_id": repo_data.get("id"),
                        "owner": owner_name or (repo_data.get("full_name", "").split("/")[0] if "/" in repo_data.get("full_name", "") else ""),
                        "name": repo_data.get("name"),
                        "full_name": repo_data.get("full_name"),
                        "private": bool(repo_data.get("private", False)),
                        "visibility": repo_data.get("visibility", "private" if repo_data.get("private") else "public"),
                        "default_branch": repo_data.get("default_branch", "main"),
                        "html_url": repo_data.get("html_url"),
                        "clone_url": repo_data.get("clone_url"),
                        "language": repo_data.get("language"),
                        "size": repo_data.get("size", 0),
                        "archived": bool(repo_data.get("archived", False)),
                        "disabled": bool(repo_data.get("disabled", False)),
                        "pushed_at": repo_data.get("pushed_at"),
                        "updated_at": repo_data.get("updated_at"),
                    }
                    all_repos.append(parsed)

                total_count = data.get("total_count", len(all_repos))
                if len(all_repos) >= total_count or len(raw_repos) < per_page:
                    break

                page += 1

        logger.info("Discovered %d installation repositories total across %d pages", len(all_repos), page)
        return all_repos
