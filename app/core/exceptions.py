"""
Purpose: Custom application exception hierarchy.

Responsibilities:
- Define specific exception classes for authentication, configuration, GitHub API, and token generation errors.

Dependencies:
- None

Usage:
    from app.core.exceptions import AuthenticationError, ConfigurationError

    raise ConfigurationError("Missing GITHUB_APP_ID")
"""


class SecureGuardError(Exception):
    """Base exception for all SecureGuard errors."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class ConfigurationError(SecureGuardError):
    """Raised when environment or application configuration is invalid or missing."""
    pass


class AuthenticationError(SecureGuardError):
    """Raised when GitHub App authentication or authorization fails."""
    pass


class TokenGenerationError(AuthenticationError):
    """Raised when GitHub App JWT generation or installation token exchange fails."""
    pass


class GitHubAPIError(SecureGuardError):
    """Raised when an HTTP error occurs while communicating with GitHub API."""

    def __init__(self, message: str, status_code: int = 500) -> None:
        super().__init__(message)
        self.status_code = status_code
