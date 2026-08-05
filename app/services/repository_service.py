"""
Purpose: Service for downloading and extracting GitHub repositories.

Responsibilities:
- Authenticate and download repository tarballs using Installation Access Tokens.
- Safely extract contents to a temporary directory.
- Ensure temporary files and directories can be cleaned up securely.

Dependencies:
- httpx
- tarfile
- io
- pathlib.Path
- tempfile
- shutil
- app.auth.github_auth.GitHubAuthManager
- app.core.exceptions.GitHubAPIError
- app.core.logging.get_logger

Usage:
    repo_service = RepositoryService(auth_manager)
    repo_path = await repo_service.download_repository(owner, repo, commit_sha, install_id)
    # ... use repo_path ...
    repo_service.cleanup_repository(repo_path)
"""

import io
import shutil
import tarfile
import tempfile
from pathlib import Path
from typing import Optional

import httpx
from app.auth.github_auth import GitHubAuthManager
from app.core.exceptions import GitHubAPIError
from app.core.logging import get_logger

logger = get_logger(__name__)


class RepositoryService:
    """Service to handle cloning or downloading repositories for scanning."""

    def __init__(self, auth_manager: GitHubAuthManager, base_url: str = "https://api.github.com") -> None:
        self.auth_manager = auth_manager
        self.base_url = base_url.rstrip("/")

    async def download_repository(self, owner: str, repo: str, commit_sha: str, installation_id: Optional[int] = None) -> Path:
        """Download and extract a repository tarball for a specific commit."""
        token = await self.auth_manager.get_installation_token(installation_id)
        
        url = f"{self.base_url}/repos/{owner}/{repo}/tarball/{commit_sha}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        # Use httpx.AsyncClient with follow_redirects since tarball endpoint usually redirects to a CDN
        async with httpx.AsyncClient(follow_redirects=True) as client:
            logger.info("Downloading repository %s/%s at commit %s", owner, repo, commit_sha)
            response = await client.get(url, headers=headers, timeout=60.0)

            if response.status_code != 200:
                raise GitHubAPIError(
                    f"Failed to download repository tarball: {response.text}",
                    status_code=response.status_code,
                )

            # Create a secure temporary directory
            # Put it in a specific 'scratch/tmp_scans' directory inside the project root for easier management if desired,
            # or just use system temp. We'll use system temp.
            temp_dir = Path(tempfile.mkdtemp(prefix=f"sg_scan_{owner}_{repo}_"))
            
            # Extract tarball
            try:
                tarball = tarfile.open(fileobj=io.BytesIO(response.content), mode="r:gz")
                # The tarball top-level directory usually has the format: owner-repo-commitsha
                # We extract everything into our temp_dir
                tarball.extractall(path=temp_dir)
                logger.info("Successfully extracted repository to %s", temp_dir)
                return temp_dir
            except Exception as e:
                # Cleanup if extraction fails
                self.cleanup_repository(temp_dir)
                logger.error("Failed to extract repository tarball: %s", str(e))
                raise GitHubAPIError(f"Failed to extract repository tarball: {str(e)}") from e

    def cleanup_repository(self, target_dir: Path) -> None:
        """Safely delete the temporary repository directory."""
        if target_dir and target_dir.exists() and target_dir.is_dir():
            try:
                shutil.rmtree(target_dir)
                logger.info("Cleaned up temporary directory %s", target_dir)
            except Exception as e:
                logger.error("Failed to clean up directory %s: %s", target_dir, str(e))
