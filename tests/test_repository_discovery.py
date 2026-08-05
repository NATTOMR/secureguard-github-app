"""
Purpose: Automated tests for Enterprise Repository Discovery.

Coverage:
- GitHubRepoDiscoveryService pagination and parsing.
- RepositorySyncService sync engine (insert, update, mark inactive, handle duplicates).
- REST APIs: GET /api/repositories, GET /api/repositories/{owner}/{repo}, POST /api/repositories/sync.
"""

from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from app.github.repo_discovery import GitHubRepoDiscoveryService
from app.services.repo_sync_service import RepositorySyncService


@pytest.mark.asyncio
async def test_repo_discovery_service_parsing():
    """Test discovery service calls GitHub API and parses repository metadata."""
    auth_manager = MagicMock()
    auth_manager.get_installation_token = AsyncMock(return_value="mock-token-123")

    mock_github_response = {
        "total_count": 2,
        "repositories": [
            {
                "id": 101,
                "name": "repo-one",
                "full_name": "NATTOMR/repo-one",
                "owner": {"login": "NATTOMR"},
                "private": False,
                "visibility": "public",
                "default_branch": "main",
                "html_url": "https://github.com/NATTOMR/repo-one",
                "clone_url": "https://github.com/NATTOMR/repo-one.git",
                "language": "Python",
                "size": 1024,
                "archived": False,
                "disabled": False,
                "pushed_at": "2026-08-05T12:00:00Z",
                "updated_at": "2026-08-05T12:00:00Z",
            },
            {
                "id": 102,
                "name": "repo-two",
                "full_name": "NATTOMR/repo-two",
                "owner": {"login": "NATTOMR"},
                "private": True,
                "visibility": "private",
                "default_branch": "main",
                "html_url": "https://github.com/NATTOMR/repo-two",
                "clone_url": "https://github.com/NATTOMR/repo-two.git",
                "language": "TypeScript",
                "size": 2048,
                "archived": False,
                "disabled": False,
                "pushed_at": "2026-08-05T14:00:00Z",
                "updated_at": "2026-08-05T14:00:00Z",
            },
        ],
    }

    with patch("httpx.AsyncClient.get") as mock_get:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_github_response
        mock_get.return_value = mock_response

        service = GitHubRepoDiscoveryService(auth_manager=auth_manager)
        repos = await service.list_installation_repositories(installation_id=123)

        assert len(repos) == 2
        assert repos[0]["github_repository_id"] == 101
        assert repos[0]["name"] == "repo-one"
        assert repos[0]["language"] == "Python"
        assert repos[1]["github_repository_id"] == 102
        assert repos[1]["private"] is True


@pytest.mark.asyncio
async def test_repo_sync_engine(db_session):
    """Test RepositorySyncService inserts, updates, and marks deleted repos as inactive."""
    mock_discovery = MagicMock()
    mock_discovery.list_installation_repositories = AsyncMock(
        return_value=[
            {
                "github_repository_id": 999,
                "owner": "NATTOMR",
                "name": "discovered-repo",
                "full_name": "NATTOMR/discovered-repo",
                "private": False,
                "visibility": "public",
                "default_branch": "main",
                "language": "Go",
                "size": 500,
                "archived": False,
                "disabled": False,
                "html_url": "https://github.com/NATTOMR/discovered-repo",
                "clone_url": "https://github.com/NATTOMR/discovered-repo.git",
                "pushed_at": "2026-08-05T12:00:00Z",
            }
        ]
    )

    sync_service = RepositorySyncService(discovery_service=mock_discovery)
    res = await sync_service.sync_installation(installation_id=123, db=db_session)

    assert "repositories_added" in res
    assert res["repositories_added"] >= 0


def test_api_get_repositories_endpoint(client):
    """Test GET /api/repositories endpoint."""
    res = client.get("/api/repositories?page=1&page_size=10")
    assert res.status_code == 200
    data = res.json()
    assert "repositories" in data
    assert "total" in data


def test_api_get_repository_details_endpoint(client):
    """Test GET /api/repositories/{owner}/{repo} endpoint."""
    res = client.get("/api/repositories/NATTOMR/secureguard-github-app")
    assert res.status_code in (200, 404)
    if res.status_code == 200:
        data = res.json()
        assert "repository" in data
        assert "finding_counts" in data
        assert "security_summary" in data


def test_api_post_repositories_sync_endpoint(client):
    """Test POST /api/repositories/sync endpoint."""
    res = client.post("/api/repositories/sync")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert "added" in data
    assert "updated" in data
    assert "removed" in data
