"""
Purpose: Authentication status and test routes.

Responsibilities:
- Provide `GET /auth/status` to check GitHub App config status.
- Provide `GET /auth/test` to test live authentication with GitHub API.

Dependencies:
- fastapi.APIRouter, Depends, HTTPException, status
- app.core.config.get_settings, Settings
- app.auth.github_auth.GitHubAuthManager
- app.github.client.GitHubClient
- app.schemas.auth.AuthStatusResponse, AuthTestResponse

Usage:
    Included in FastAPI router.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from app.auth.github_auth import GitHubAuthManager
from app.core.config import Settings, get_settings
from app.core.exceptions import SecureGuardError
from app.github.client import GitHubClient
from app.schemas.auth import AuthStatusResponse, AuthTestResponse

router = APIRouter(prefix="/auth", tags=["GitHub Authentication"])


def get_github_client(settings: Settings = Depends(get_settings)) -> GitHubClient:
    """Dependency provider for GitHubClient."""
    auth_manager = GitHubAuthManager(settings)
    return GitHubClient(auth_manager)


@router.get(
    "/status",
    response_model=AuthStatusResponse,
    status_code=status.HTTP_200_OK,
    summary="Check Authentication Configuration Status",
    description="Returns whether GitHub App credentials and configuration are properly set.",
)
async def get_auth_status(settings: Settings = Depends(get_settings)) -> AuthStatusResponse:
    """Check configuration and authentication readiness."""
    has_app_id = bool(settings.GITHUB_APP_ID)
    has_key = bool(settings.effective_private_key_path)
    is_ready = has_app_id and has_key

    return AuthStatusResponse(
        authenticated=is_ready,
        app_id=str(settings.GITHUB_APP_ID) if settings.GITHUB_APP_ID else None,
        installation_id=str(settings.GITHUB_INSTALLATION_ID) if settings.GITHUB_INSTALLATION_ID else None,
        environment=settings.APP_ENV,
    )


@router.get(
    "/test",
    response_model=AuthTestResponse,
    status_code=status.HTTP_200_OK,
    summary="Test GitHub App Authentication",
    description="Authenticates against GitHub API using generated JWT to verify credentials.",
)
async def test_auth(
    client: GitHubClient = Depends(get_github_client),
    settings: Settings = Depends(get_settings),
) -> AuthTestResponse:
    """Test live authentication against GitHub API."""
    try:
        settings.validate_github_config()
        app_info = await client.get_authenticated_app()
        app_name = app_info.get("name", settings.APP_NAME)
        return AuthTestResponse(
            status="success",
            message="GitHub App authenticated successfully.",
            app_name=app_name,
        )
    except SecureGuardError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"GitHub App authentication failed: {e.message}",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected authentication error: {str(e)}",
        )
