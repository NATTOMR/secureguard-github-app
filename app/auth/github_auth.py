"""
Purpose: Centralized GitHub App authentication manager orchestrator.

Responsibilities:
- Combine JWT generation and installation token caching services.
- Provide unified entry point for authenticating GitHub App requests.

Dependencies:
- app.core.config.Settings
- app.auth.jwt_generator.JWTGenerator
- app.auth.installation_token.InstallationTokenService

Usage:
    auth_manager = GitHubAuthManager(settings)
    jwt_token = auth_manager.get_app_jwt()
    installation_token = await auth_manager.get_installation_token(installation_id)
"""

from typing import Optional
from app.auth.installation_token import InstallationTokenService
from app.auth.jwt_generator import JWTGenerator
from app.core.config import Settings


class GitHubAuthManager:
    """High-level GitHub App authentication coordinator."""

    def __init__(
        self,
        settings: Settings,
        jwt_generator: Optional[JWTGenerator] = None,
        token_service: Optional[InstallationTokenService] = None,
    ) -> None:
        self.settings = settings
        self.jwt_generator = jwt_generator or JWTGenerator(settings)
        self.token_service = token_service or InstallationTokenService(self.jwt_generator)

    def get_app_jwt(self) -> str:
        """Generate a signed GitHub App JWT."""
        return self.jwt_generator.generate_jwt()

    async def get_installation_token(self, installation_id: Optional[int] = None) -> str:
        """Retrieve a cached or refreshed installation access token."""
        target_id = installation_id or self.settings.GITHUB_INSTALLATION_ID
        if not target_id:
            from app.core.exceptions import AuthenticationError
            raise AuthenticationError("Installation ID is required to acquire an installation access token.")
        return await self.token_service.get_installation_token(target_id)
