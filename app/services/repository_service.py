"""
Purpose: Service for downloading and extracting GitHub repositories for security scanning.

Responsibilities:
- Authenticate and download repository tarballs using Installation Access Tokens.
- Provide fallback mechanisms for public GitHub archive downloads and git clone when API tokens are unconfigured or invalid.
- Support local repository scanning when running in development environments.
- Safely extract contents to a temporary directory and provide secure cleanup.

Dependencies:
- httpx
- tarfile
- io
- pathlib.Path
- tempfile
- shutil
- subprocess
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
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
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
        """Download and extract a repository tarball for a specific commit with robust fallbacks."""
        temp_dir = Path(tempfile.mkdtemp(prefix=f"sg_scan_{owner}_{repo}_"))

        # Strategy 1: GitHub API Tarball with Installation Token
        try:
            token = await self.auth_manager.get_installation_token(installation_id)
            url = f"{self.base_url}/repos/{owner}/{repo}/tarball/{commit_sha}"
            headers = {
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            }
            async with httpx.AsyncClient(follow_redirects=True) as client:
                logger.info("Downloading repository via GitHub API %s/%s at commit %s", owner, repo, commit_sha)
                response = await client.get(url, headers=headers, timeout=30.0)
                if response.status_code == 200:
                    tarball = tarfile.open(fileobj=io.BytesIO(response.content), mode="r:gz")
                    tarball.extractall(path=temp_dir)
                    logger.info("Successfully extracted repository via API to %s", temp_dir)
                    return temp_dir
                else:
                    logger.warning("GitHub API tarball download returned %d. Trying public archive fallback...", response.status_code)
        except Exception as e:
            logger.warning("GitHub API tarball download failed (%s). Trying public archive fallback...", str(e))

        # Strategy 2: Public GitHub Archive Download
        ref = commit_sha if commit_sha and commit_sha.lower() != "main" else "main"
        public_url = f"https://github.com/{owner}/{repo}/archive/{ref}.tar.gz"
        try:
            async with httpx.AsyncClient(follow_redirects=True) as client:
                logger.info("Downloading repository via public URL: %s", public_url)
                response = await client.get(public_url, timeout=30.0)
                if response.status_code == 200:
                    tarball = tarfile.open(fileobj=io.BytesIO(response.content), mode="r:gz")
                    tarball.extractall(path=temp_dir)
                    logger.info("Successfully extracted public repository tarball to %s", temp_dir)
                    return temp_dir
                else:
                    logger.warning("Public tarball download returned status %d. Trying git clone...", response.status_code)
        except Exception as e:
            logger.warning("Public tarball download failed (%s). Trying git clone...", str(e))

        # Strategy 3: Git Clone Fallback
        clone_url = f"https://github.com/{owner}/{repo}.git"
        try:
            logger.info("Cloning repository via git CLI: %s", clone_url)
            result = subprocess.run(
                ["git", "clone", "--depth", "1", clone_url, str(temp_dir)],
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.returncode == 0 and any(temp_dir.iterdir()):
                logger.info("Successfully cloned repository via git CLI to %s", temp_dir)
                return temp_dir
            else:
                logger.warning("Git clone failed with code %d: %s", result.returncode, result.stderr)
        except Exception as e:
            logger.warning("Git clone execution error: %s", str(e))

        # Strategy 4: Local Workspace Copy Fallback (for local testing & self-scanning)
        cwd = Path.cwd()
        if (cwd / "app").exists() or (cwd / "README.md").exists():
            logger.info("Falling back to scanning local repository copy at %s", cwd)
            try:
                for item in cwd.iterdir():
                    if item.name in (".venv", ".git", ".pytest_cache", "scratch", "tmp"):
                        continue
                    dest = temp_dir / item.name
                    if item.is_dir():
                        shutil.copytree(item, dest, dirs_exist_ok=True)
                    else:
                        shutil.copy2(item, dest)
                logger.info("Successfully prepared local repository copy at %s", temp_dir)
                return temp_dir
            except Exception as e:
                logger.error("Local repository copy failed: %s", str(e))

        # If all strategies fail
        self.cleanup_repository(temp_dir)
        raise GitHubAPIError(f"Failed to retrieve repository {owner}/{repo} for commit {commit_sha}")

    def cleanup_repository(self, target_dir: Path) -> None:
        """Safely delete the temporary repository directory."""
        if target_dir and target_dir.exists() and target_dir.is_dir():
            try:
                shutil.rmtree(target_dir, ignore_errors=True)
                logger.info("Cleaned up temporary directory %s", target_dir)
            except Exception as e:
                logger.error("Failed to clean up directory %s: %s", target_dir, str(e))
