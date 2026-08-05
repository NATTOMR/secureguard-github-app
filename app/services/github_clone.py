"""
Purpose: Service for cloning and cleaning up target repositories for scanning.

Responsibilities:
- Perform shallow git clones (--depth 1) into temporary workspace directories.
- Support authenticated clone URLs using GitHub Installation tokens.
- Safely clean up temporary repository directories after scanning.

Dependencies:
- tempfile
- subprocess
- shutil
- pathlib.Path
- app.core.logging.get_logger
- app.core.exceptions.GitHubAPIError

Usage:
    clone_service = GitHubCloneService()
    temp_path = clone_service.clone_repository(repo_url="...", token="...", commit_sha="...")
    # ... scan ...
    clone_service.cleanup_repository(temp_path)
"""

import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from app.core.exceptions import GitHubAPIError
from app.core.logging import get_logger

logger = get_logger(__name__)


class GitHubCloneService:
    """Service to handle shallow git clones and temp directory management."""

    def __init__(self, base_temp_dir: Optional[str] = None) -> None:
        self.base_temp_dir = base_temp_dir

    def clone_repository(
        self,
        clone_url: str,
        token: Optional[str] = None,
        commit_sha: Optional[str] = None,
    ) -> Path:
        """Perform a shallow clone (--depth 1) of the target repository into a temp directory."""
        # Insert auth token into HTTPS clone URL if provided
        auth_url = clone_url
        if token and clone_url.startswith("https://"):
            auth_url = clone_url.replace("https://", f"https://x-access-token:{token}@")

        # Create temporary workspace directory
        temp_dir = Path(tempfile.mkdtemp(prefix="sg_clone_", dir=self.base_temp_dir))
        logger.info("Cloning repository into temporary directory: %s", temp_dir)

        cmd = ["git", "clone", "--depth", "1", auth_url, str(temp_dir)]
        if commit_sha:
            # Note: shallow clone default clones default branch head; if specific commit needed, fetch can be used
            pass

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=180,
            )
            logger.info("Successfully cloned repository to %s", temp_dir)
            return temp_dir
        except subprocess.CalledProcessError as e:
            self.cleanup_repository(temp_dir)
            logger.error("Git clone failed (exit code %d): %s", e.returncode, e.stderr)
            raise GitHubAPIError(f"Failed to clone repository: {e.stderr}") from e
        except subprocess.TimeoutExpired as e:
            self.cleanup_repository(temp_dir)
            logger.error("Git clone timed out for %s", clone_url)
            raise GitHubAPIError("Git clone execution timed out.") from e

    def cleanup_repository(self, target_dir: Optional[Path]) -> None:
        """Safely delete the temporary repository directory."""
        if target_dir and target_dir.exists() and target_dir.is_dir():
            try:
                shutil.rmtree(target_dir, ignore_errors=True)
                logger.info("Successfully cleaned up repository directory %s", target_dir)
            except Exception as e:
                logger.error("Failed to cleanup repository directory %s: %s", target_dir, str(e))
