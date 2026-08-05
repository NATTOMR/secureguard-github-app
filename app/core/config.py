"""
Purpose: Centralized application configuration loader using Pydantic Settings v2.

Responsibilities:
- Parse environment variables and `.env` files into strongly-typed settings objects.
- Validate GitHub App configuration settings.
- Expose single cached configuration instance (`get_settings`).

Dependencies:
- functools.lru_cache
- typing.Optional
- pydantic.Field
- pydantic_settings.BaseSettings
- app.core.exceptions.ConfigurationError

Usage:
    from app.core.config import get_settings

    settings = get_settings()
    settings.validate_github_config()
"""

from functools import lru_cache
from typing import Any, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from app.core.exceptions import ConfigurationError


class Settings(BaseSettings):
    """Application Settings powered by Pydantic BaseSettings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # General App Config
    APP_NAME: str = Field(default="SecureGuard", description="Application Name")
    APP_VERSION: str = Field(default="0.1.0", description="Application Version")
    APP_ENV: str = Field(default="development", description="Environment (development, staging, production)")
    DEBUG: bool = Field(default=False, description="Debug mode flag")
    LOG_LEVEL: str = Field(default="INFO", description="Logging level (DEBUG, INFO, WARNING, ERROR)")
    HOST: str = Field(default="0.0.0.0", description="Bind host address")
    PORT: int = Field(default=8000, description="Bind port number")

    # GitHub App Credentials
    GITHUB_APP_ID: Optional[int] = Field(default=4492546, description="GitHub App ID")
    GITHUB_CLIENT_ID: Optional[str] = Field(default=None, description="GitHub Client ID")
    GITHUB_INSTALLATION_ID: Optional[int] = Field(default=None, description="GitHub Installation ID")
    GITHUB_WEBHOOK_SECRET: Optional[str] = Field(default=None, description="GitHub Webhook Secret")
    GITHUB_PRIVATE_KEY_PATH: Optional[str] = Field(default=None, description="Path or content of GitHub App RSA private key")
    PRIVATE_KEY_PATH: Optional[str] = Field(default=None, description="Alias for private key path")

    # Scanner Configuration
    GITLEAKS_BINARY: str = Field(default="gitleaks", description="Path or command for Gitleaks CLI binary")
    TEMP_SCAN_DIR: str = Field(default="scratch/tmp_scans", description="Directory for temporary repository clones")
    SCAN_TIMEOUT: int = Field(default=120, description="Scanner execution timeout in seconds")
    MAX_REPO_SIZE_MB: int = Field(default=500, description="Maximum allowed repository size in MB")

    # Checks API Configuration
    GITHUB_CHECKS_ENABLED: bool = Field(default=True, description="Enable GitHub Checks API reporting")
    MAX_ANNOTATIONS: int = Field(default=50, description="Maximum annotations per GitHub Checks API request")
    CHECK_RUN_NAME: str = Field(default="SecureGuard Security Scan", description="Name of the GitHub Check Run")

    # Database Configuration
    DATABASE_URL: str = Field(default="sqlite:///./secureguard.db", description="Database connection URL")

    @field_validator("GITHUB_APP_ID", mode="before")
    @classmethod
    def sanitize_app_id(cls, v: Any) -> Any:
        if v == "":
            return 4492546
        return v

    @field_validator("GITHUB_INSTALLATION_ID", mode="before")
    @classmethod
    def sanitize_installation_id(cls, v: Any) -> Any:
        if v == "":
            return None
        return v

    @property
    def effective_private_key_path(self) -> Optional[str]:
        """Return GITHUB_PRIVATE_KEY_PATH or PRIVATE_KEY_PATH fallback."""
        return self.GITHUB_PRIVATE_KEY_PATH or self.PRIVATE_KEY_PATH

    def validate_github_config(self) -> None:
        """Validate that all required GitHub App settings are configured."""
        missing = []
        if not self.GITHUB_APP_ID:
            missing.append("GITHUB_APP_ID")
        if not self.effective_private_key_path:
            missing.append("GITHUB_PRIVATE_KEY_PATH / PRIVATE_KEY_PATH")

        if missing:
            raise ConfigurationError(
                f"Missing required GitHub App configuration parameters: {', '.join(missing)}"
            )


@lru_cache
def get_settings() -> Settings:
    """Return a cached instance of the application settings."""
    return Settings()
