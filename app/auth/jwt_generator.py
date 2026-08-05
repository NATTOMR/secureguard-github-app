"""
Purpose: GitHub App RS256 JWT Generator.

Responsibilities:
- Create RS256 signed JSON Web Tokens for GitHub App identity authentication.
- Manage token expiration (< 10 minutes) and clock skew window.

Dependencies:
- time
- jwt (PyJWT)
- app.core.config.Settings
- app.core.security.load_private_key
- app.core.logging.get_logger
- app.core.exceptions.TokenGenerationError

Usage:
    generator = JWTGenerator(settings)
    token = generator.generate_jwt()
"""

import time
from typing import Optional
import jwt

from app.core.config import Settings
from app.core.exceptions import TokenGenerationError
from app.core.logging import get_logger
from app.core.security import load_private_key

logger = get_logger(__name__)


class JWTGenerator:
    """Generates RS256-signed JWTs for GitHub App authentication."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def generate_jwt(self, app_id: Optional[int] = None, private_key_path: Optional[str] = None) -> str:
        """Generate a signed GitHub App JWT valid for 9 minutes."""
        effective_app_id = app_id or self.settings.GITHUB_APP_ID
        effective_key_path = private_key_path or self.settings.effective_private_key_path

        if not effective_app_id:
            raise TokenGenerationError("Cannot generate JWT: GITHUB_APP_ID is not configured.")
        if not effective_key_path:
            raise TokenGenerationError("Cannot generate JWT: Private key path is not configured.")

        try:
            private_key_bytes = load_private_key(effective_key_path)
            now = int(time.time())

            # GitHub requires JWT expiration <= 10 minutes. We set to 9 minutes with 60s iat clock skew allowance.
            payload = {
                "iat": now - 60,
                "exp": now + (9 * 60),
                "iss": str(effective_app_id),
            }

            jwt_token = jwt.encode(payload, private_key_bytes, algorithm="RS256")
            logger.info("Successfully generated GitHub App JWT for App ID %s", effective_app_id)
            return jwt_token
        except Exception as e:
            logger.error("Failed to generate GitHub App JWT: %s", str(e))
            raise TokenGenerationError(f"Failed to generate GitHub App JWT: {str(e)}") from e
