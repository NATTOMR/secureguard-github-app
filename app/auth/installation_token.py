"""
Purpose: Installation Access Token management service.

Responsibilities:
- Exchange GitHub App JWT for installation access tokens.
- Cache access tokens in memory and auto-refresh before expiration.

Dependencies:
- time
- datetime
- httpx
- app.auth.jwt_generator.JWTGenerator
- app.core.exceptions.TokenGenerationError, GitHubAPIError
- app.core.logging.get_logger
- app.core.security.mask_secret

Usage:
    token_service = InstallationTokenService(jwt_generator)
    token = await token_service.get_installation_token(installation_id)
"""

from datetime import datetime, timezone
import time
from typing import Dict, Optional, Tuple
import httpx

from app.auth.jwt_generator import JWTGenerator
from app.core.exceptions import GitHubAPIError, TokenGenerationError
from app.core.logging import get_logger
from app.core.security import mask_secret

logger = get_logger(__name__)


class InstallationTokenService:
    """Service to fetch, cache, and refresh GitHub Installation Access Tokens."""

    def __init__(self, jwt_generator: JWTGenerator, github_api_url: str = "https://api.github.com") -> None:
        self.jwt_generator = jwt_generator
        self.github_api_url = github_api_url.rstrip("/")
        # In-memory cache mapping installation_id -> (token: str, expires_at_timestamp: float)
        self._token_cache: Dict[int, Tuple[str, float]] = {}

    async def get_installation_token(self, installation_id: int) -> str:
        """Retrieve a valid installation access token, using cache if available."""
        now = time.time()
        
        # Check cache (refresh 60 seconds before actual expiration)
        if installation_id in self._token_cache:
            cached_token, expires_at = self._token_cache[installation_id]
            if now < (expires_at - 60):
                logger.debug("Cache hit for installation token (ID: %s)", installation_id)
                return cached_token
            logger.info("Installation token expired or near expiration for ID %s. Refreshing...", installation_id)

        # Cache miss or expired token -> fetch new token
        token, expires_at = await self._fetch_new_installation_token(installation_id)
        self._token_cache[installation_id] = (token, expires_at)
        logger.info(
            "Acquired new installation token for ID %s (token: %s, expires in %ds)",
            installation_id,
            mask_secret(token),
            int(expires_at - now),
        )
        return token

    async def _fetch_new_installation_token(self, installation_id: int) -> Tuple[str, float]:
        """Fetch a new installation token from GitHub API using JWT."""
        jwt_token = self.jwt_generator.generate_jwt()
        url = f"{self.github_api_url}/app/installations/{installation_id}/access_tokens"
        headers = {
            "Authorization": f"Bearer {jwt_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(url, headers=headers, timeout=10.0)
            except Exception as e:
                logger.error("HTTP network failure fetching installation token: %s", str(e))
                raise TokenGenerationError(f"Network error contacting GitHub API: {str(e)}") from e

            if response.status_code != 201:
                logger.error(
                    "GitHub API returned error %d fetching installation token: %s",
                    response.status_code,
                    response.text,
                )
                raise GitHubAPIError(
                    f"Failed to fetch installation token for installation ID {installation_id}: {response.text}",
                    status_code=response.status_code,
                )

            data = response.json()
            token = data.get("token")
            expires_at_str = data.get("expires_at")

            if not token or not expires_at_str:
                raise TokenGenerationError("GitHub API response missing token or expires_at field.")

            # Parse ISO 8601 timestamp string (e.g. 2026-08-05T14:30:00Z)
            expires_dt = datetime.fromisoformat(expires_at_str.replace("Z", "+00:00"))
            expires_timestamp = expires_dt.timestamp()

            return token, expires_timestamp
