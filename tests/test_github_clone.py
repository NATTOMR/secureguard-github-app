"""
Purpose: Unit tests for GitHubCloneService.

Responsibilities:
- Verify clone_repository method invocation.
- Verify cleanup_repository method removes temp directory.

Dependencies:
- pytest
- unittest.mock
- app.services.github_clone.GitHubCloneService

Usage:
    pytest tests/test_github_clone.py -v
"""

from pathlib import Path
import tempfile
from unittest.mock import patch, MagicMock
import pytest
from app.services.github_clone import GitHubCloneService


def test_clone_service_cleanup():
    """Test cleanup_repository deletes temp directory."""
    clone_service = GitHubCloneService()
    temp_dir = Path(tempfile.mkdtemp(prefix="test_cleanup_"))
    assert temp_dir.exists()

    clone_service.cleanup_repository(temp_dir)
    assert not temp_dir.exists()


@patch("subprocess.run")
def test_clone_repository_success(mock_run):
    """Test clone_repository issues correct git command."""
    mock_run.return_value = MagicMock(returncode=0)

    clone_service = GitHubCloneService()
    path = clone_service.clone_repository(
        clone_url="https://github.com/octocat/Hello-World.git",
        token="mock_token",
    )

    assert path.exists()
    assert mock_run.called
    cmd_args = mock_run.call_args[0][0]
    assert cmd_args[0] == "git"
    assert cmd_args[1] == "clone"
    assert "--depth" in cmd_args
    assert "1" in cmd_args

    clone_service.cleanup_repository(path)
